// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package stats

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/client"
	"github.com/aws/aws-app-mesh-agent/agent/config"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type Snapshotter struct {
	Snapshot    map[string]*io_prometheus_client.MetricFamily
	Delta       map[string]*io_prometheus_client.MetricFamily
	HttpClient  *retryablehttp.Client
	HttpRequest *retryablehttp.Request
}

func (snapshotter *Snapshotter) StartSnapshot(agentConfig config.AgentConfig) {
	httpClient, err := client.CreateRetryableHttpClientForEnvoyServer(agentConfig)
	httpClient.HTTPClient.Timeout = EnvoyStatsClientHttpTimeout
	if err != nil {
		log.Errorf("unable to create Retryable Http Client: %v", err)
		return
	}
	snapshotter.HttpClient = httpClient
	queryParams := url.Values{}
	queryParams.Add(usedOnlyQueryKey, "")
	queryString := constructQueryString(queryParams)
	requestUrl := getEnvoyStatsUrl(&agentConfig, queryString)
	statsRequest, err := client.CreateRetryableAgentRequest(http.MethodGet, requestUrl, nil)
	if err != nil {
		log.Errorf("failed to create Retryable Http request, requestUrl: %s, error: %v", requestUrl, err)
		return
	}
	snapshotter.HttpRequest = statsRequest

	ticker := time.NewTicker(snapshotInterval)
	// Loop forever
	for {
		select {
		case <-ticker.C:
			snapshotter.makeSnapshot()
		}
	}
}

// makeSnapshot capture snapshots once invoked, it will automatically compute delta once we have enough snapshots.
// The newly captured snapshot will be saved to snapshotter.
func (snapshotter *Snapshotter) makeSnapshot() {
	statsBody, err := getStatsFromEnvoy(snapshotter.HttpClient, snapshotter.HttpRequest)
	if err != nil {
		log.Errorf("failed to get stats from Envoy, error: %v", err)
		return
	}
	snapshot, err := processPrometheusStats(statsBody)
	if err != nil {
		log.Errorf("error processing Prometheus stats: %v", err)
		return
	}
	if snapshot != nil {
		// We will compute the delta and then save or overwrite the newly captured snapshot.
		snapshotter.computeDelta(snapshot)
		snapshotter.Snapshot = snapshot
	}
}

// computeDelta will compute the delta between the given snapshots.
// If there is no previously captured snapshot, which means we just got the very first snapshot,
// we will use the snapshot as the delta value.
//
// The dependency library does not support protobuf v2 APIs. See their README: https://github.com/prometheus/client_model
// Possibly switching to OpenMetrics(https://openmetrics.io/) when it is ready in the future.
func (snapshotter *Snapshotter) computeDelta(newSnapshot map[string]*io_prometheus_client.MetricFamily) {
	if newSnapshot == nil {
		log.Errorf("the newSnapshot should exist to compute the snapshot")
		return
	}

	if snapshotter.Snapshot == nil {
		log.Debugf("Using the new snapshot as delta since there is no previously captured snapshot yet.")
		snapshotter.Delta = newSnapshot
		return
	}

	newDelta := make(map[string]*io_prometheus_client.MetricFamily)
	for metricFamilyKey, newMetricFamily := range newSnapshot {
		// It is possible that there are new metrics emitted in the new snapshot, in which case the old snapshot won't
		// have the corresponding metrics. This would result in metricFamilyKey does not exist in the existing snapshot,
		// in which case the oldMetricFamily passed in would simply be nil.
		snapshotter.computeDeltaForMetricFamily(snapshotter.Snapshot[metricFamilyKey], newMetricFamily, newDelta)

	}
	// We only update Delta once the new delta is completely computed.
	snapshotter.Delta = newDelta
}

func (snapshotter *Snapshotter) computeDeltaForMetricFamily(oldMetricFamily, newMetricFamily *io_prometheus_client.MetricFamily, delta map[string]*io_prometheus_client.MetricFamily) {
	if oldMetricFamily == nil && newMetricFamily == nil {
		log.Error("both metric families are empty, cannot compute delta")
		return
	}

	// The assumption here is that, the metric family from new snapshot should always exist when computing the
	// delta. This is because the metric families from old snapshot should be a subset of the metric families from
	// new snapshot.
	if newMetricFamily == nil {
		log.Debugf("metricFamily from new snapshot must exist to compute the delta")
		return
	}

	metricName := newMetricFamily.GetName()
	metricType := newMetricFamily.GetType()

	if _, ok := delta[metricName]; !ok {
		// Create deltaEntry if it does not exist
		delta[metricName] = &io_prometheus_client.MetricFamily{
			Name:   &metricName,
			Type:   &metricType,
			Metric: make([]*io_prometheus_client.Metric, len(newMetricFamily.Metric)),
		}
	}

	// Create a metric lookup
	metricLookup := make(map[string]*io_prometheus_client.Metric)
	if oldMetricFamily != nil {
		for _, oldMetric := range oldMetricFamily.Metric {
			metricKey := generateMetricKey(oldMetric.Label)
			metricLookup[metricKey] = oldMetric
		}
	}

	for metricIndex, newMetricFamilyMetric := range newMetricFamily.Metric {
		deltaMetric := &io_prometheus_client.Metric{Label: newMetricFamilyMetric.GetLabel()}
		metricKey := generateMetricKey(newMetricFamilyMetric.GetLabel())
		oldMetric := metricLookup[metricKey]
		switch metricType {
		case io_prometheus_client.MetricType_COUNTER:
			{
				newValue := newMetricFamilyMetric.GetCounter().GetValue()
				// We only compute delta when the same metric label was matched. Note that the metricKey consists of
				// the labels of the metric.
				if oldMetric != nil {
					oldValue := oldMetric.GetCounter().GetValue()
					deltaMetric.Counter = &io_prometheus_client.Counter{Value: proto.Float64(newValue - oldValue)}
				} else {
					deltaMetric.Counter = &io_prometheus_client.Counter{Value: proto.Float64(newValue), Exemplar: newMetricFamilyMetric.GetCounter().GetExemplar()}
				}
			}
		case io_prometheus_client.MetricType_GAUGE:
			{
				// We don't need to compute the delta value of Gauge since itself is a metric that represents a single
				// numerical value that can arbitrarily go up and down.
				newValue := newMetricFamilyMetric.GetGauge().GetValue()
				deltaMetric.Gauge = &io_prometheus_client.Gauge{Value: proto.Float64(newValue)}
			}
		case io_prometheus_client.MetricType_UNTYPED:
			fallthrough
		case io_prometheus_client.MetricType_SUMMARY:
			// Do nothing, we are not expecting Untyped and Summary metric type.
			log.Errorf("unsupported metric type for delta computation: %s", metricType)
		case io_prometheus_client.MetricType_HISTOGRAM:
			{
				newMetricFamilyMetricHistogram := newMetricFamilyMetric.GetHistogram()
				deltaHistogram := &io_prometheus_client.Histogram{}
				if newMetricFamilyMetricHistogram.Bucket != nil {
					newBucket := newMetricFamilyMetricHistogram.GetBucket()
					deltaHistogram.Bucket = make([]*io_prometheus_client.Bucket, len(newBucket))
					for bucketIndex, newBk := range newBucket {
						deltaBucket := &io_prometheus_client.Bucket{UpperBound: newBk.UpperBound}
						// Make sure the metric with same tags exists in the old metrics and the bucket size remains the
						// same before we compute the delta. Otherwise, use the new metric as delta.
						// Note that the bucket size should not change, this is just adding a safe check.
						if oldMetric != nil && len(oldMetric.GetHistogram().Bucket) == len(newBucket) {
							oldBk := oldMetric.GetHistogram().Bucket[bucketIndex]
							deltaBucket.CumulativeCount = proto.Uint64(newBk.GetCumulativeCount() - oldBk.GetCumulativeCount())
						} else {
							deltaBucket.CumulativeCount = proto.Uint64(newBk.GetCumulativeCount())
						}
						deltaHistogram.Bucket[bucketIndex] = deltaBucket
					}
				}
				if newMetricFamilyMetricHistogram.SampleCount != nil {
					newSampleCount := newMetricFamilyMetricHistogram.GetSampleCount()
					// We only compute delta when the same metric label was matched. Note that the metricKey consists of
					// the labels of the metric.
					if oldMetric != nil {
						oldSampleCount := oldMetric.GetHistogram().GetSampleCount()
						deltaHistogram.SampleCount = proto.Uint64(newSampleCount - oldSampleCount)
					} else {
						deltaHistogram.SampleCount = proto.Uint64(newSampleCount)
					}
				}
				if newMetricFamilyMetricHistogram.SampleSum != nil {
					newSampleSum := newMetricFamilyMetricHistogram.GetSampleSum()
					if oldMetric != nil {
						oldSampleSum := oldMetric.GetHistogram().GetSampleSum()
						deltaHistogram.SampleSum = proto.Float64(newSampleSum - oldSampleSum)
					} else {
						deltaHistogram.SampleSum = proto.Float64(newSampleSum)
					}
				}
				deltaMetric.Histogram = deltaHistogram
			}
		}
		delta[metricName].Metric[metricIndex] = deltaMetric
	}
}

func generateMetricKey(labels []*io_prometheus_client.LabelPair) string {
	metricKey := ""
	for _, label := range labels {
		// Example format:
		// LabelPair{Name: "Mesh", Value: "howto-k8s-http"} - will have a metric key
		// "Mesh=howto-k8s-http;"
		metricKey += fmt.Sprintf("%s=%s;", *label.Name, *label.Value)
	}
	return metricKey
}

// Util function for snapshotter to call Envoy Stats endpoint
func getStatsFromEnvoy(httpClient *retryablehttp.Client, request *retryablehttp.Request) ([]byte, error) {
	// Send request to Envoy Stats endpoint
	start := time.Now()
	statsResponse, err := httpClient.Do(request)
	duration := time.Since(start)
	log.Debugf("Stats request took: %vms", duration.Milliseconds())

	if err != nil {
		return nil, fmt.Errorf("call to fetch stats from Envoy admin failed: %v", err)
	}

	defer statsResponse.Body.Close()

	if statsResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("envoy stats response status code not OK, error code: %v", statsResponse.StatusCode)
	}

	resBody, err := ioutil.ReadAll(statsResponse.Body)
	if err != nil {
		return resBody, fmt.Errorf("failed to read stats response retrieved from Envoy admin: %v", err)
	}
	return resBody, nil
}
