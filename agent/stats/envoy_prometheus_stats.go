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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/client"
	"github.com/aws/aws-app-mesh-agent/agent/config"

	// reference: https://github.com/prometheus/common/blob/main/expfmt/text_parse.go#L25
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type EnvoyPrometheusStatsHandler struct {
	AgentConfig     config.AgentConfig
	Limiter         *rate.Limiter
	QueryParameters url.Values
	Snapshotter     *Snapshotter
}

const (
	usedOnlyQueryKey            = "usedonly"
	filterQueryKey              = "filter"
	deltaQueryKey               = "delta"
	extendedMetricsPrefix       = "envoy_appmesh_"
	snapshotInterval            = 1 * time.Minute
	EnvoyStatsClientHttpTimeout = 5 * time.Second
)

var (
	filterQueryUsage = fmt.Sprintf("%s?%s=%s", config.AGENT_STATS_ENDPOINT_URL, filterQueryKey, QuerySet[filterQueryKey])
)

var (
	// QuerySet records the set of the supported query parameters and their allowed value.
	QuerySet = map[string]interface{}{
		usedOnlyQueryKey: nil,
		filterQueryKey:   "metrics_extension",
		deltaQueryKey:    nil,
	}
)

func (envoyPrometheusStatsHandler *EnvoyPrometheusStatsHandler) HandleStats(resWriter http.ResponseWriter, request *http.Request) {
	if !envoyPrometheusStatsHandler.Limiter.Allow() {
		http.Error(resWriter, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	// Validate the query parameters in the request before passing it to call Envoy stats endpoint.
	// Extract queryStringToEnvoy from request and generate the stats url sent to Envoy stats endpoint.
	//
	// Note that we always prepend the ENVOY_PROMETHEUS_QUERY_STRING to enforce the prometheus format.
	// See https://www.envoyproxy.io/docs/envoy/latest/operations/admin#get--stats?format=prometheus
	if queryParams, err := validateGetStatsRequest(request); err != nil {
		http.Error(resWriter, err.Error(), http.StatusBadRequest)
		return
	} else {
		envoyPrometheusStatsHandler.QueryParameters = *queryParams
	}

	// If the Delta exists, we would just return Delta directly with no further operation needed.
	if envoyPrometheusStatsHandler.QueryParameters.Has(deltaQueryKey) && envoyPrometheusStatsHandler.Snapshotter.Delta != nil {
		resWriter.WriteHeader(http.StatusOK)
		err := writeMetricsToResponse(resWriter, envoyPrometheusStatsHandler.Snapshotter.Delta)
		if err != nil {
			log.Errorf("error while writing response: %s", err)
		}
		return
	}

	// If Delta is not yet computed, most likely it is too early and we don't yet have two snapshots to compute the
	// delta. In this case we will just return the stats as it is because that is essentially the delta
	// (current stats - 0).
	//
	// Start building the request to Envoy Admin Interface for the stats.
	queryStringToEnvoy := constructQueryString(envoyPrometheusStatsHandler.QueryParameters)

	envoyStatsUrl := getEnvoyStatsUrl(&envoyPrometheusStatsHandler.AgentConfig, queryStringToEnvoy)
	log.Debugf("Full URL to query Envoy Stats Endpoint: %s", envoyStatsUrl)
	// Building the client for Envoy server
	httpClient, err := client.CreateRetryableHttpClientForEnvoyServer(envoyPrometheusStatsHandler.AgentConfig)
	httpClient.HTTPClient.Timeout = EnvoyStatsClientHttpTimeout
	if err != nil {
		http.Error(resWriter, err.Error(), http.StatusInternalServerError)
		return
	}
	statsRequest, err := client.CreateRetryableAgentRequest(http.MethodGet, envoyStatsUrl, nil)
	if err != nil {
		http.Error(resWriter, err.Error(), http.StatusInternalServerError)
		return
	}

	// Start a timer to record the response time observed from client side.
	start := time.Now()
	// Make the request to Envoy stats endpoint
	statsResponse, err := httpClient.Do(statsRequest)
	duration := time.Since(start)
	log.Debugf("Stats request took: %vms", duration.Milliseconds())

	if err != nil {
		log.Errorf("Call to fetch stats from Envoy admin failed: %s", err)
		http.Error(resWriter, "Failed to fetch stats from Envoy", http.StatusInternalServerError)
		return
	}

	if statsResponse.StatusCode != http.StatusOK {
		log.Errorf("Envoy stats response status code not OK: %v", statsResponse.Status)
		http.Error(resWriter, "Failed to fetch stats from Envoy", http.StatusInternalServerError)
		return
	}

	defer statsResponse.Body.Close()
	responseBody, err := ioutil.ReadAll(statsResponse.Body)
	if err != nil {
		log.Errorf("Failed to read stats response retreived from Envoy admin: %v", err)
		http.Error(resWriter, "Failed to fetch stats from Envoy", http.StatusInternalServerError)
		return
	}
	// Directly write the response if there is no filter query
	if !envoyPrometheusStatsHandler.QueryParameters.Has(filterQueryKey) {
		resWriter.WriteHeader(http.StatusOK)
		_, err := resWriter.Write(responseBody)
		if err != nil {
			log.Errorf("error while writing response: %s", err)
		}
		return
	}

	// Filter the stats
	filteredMetricFamilies, err := processPrometheusStats(responseBody)
	if err != nil {
		http.Error(resWriter, fmt.Sprintf("error processing prometheus stats: %s", err), http.StatusInternalServerError)
		return
	}
	resWriter.WriteHeader(http.StatusOK)
	err = writeMetricsToResponse(resWriter, filteredMetricFamilies)
	if err != nil {
		log.Errorf("error while writing response: %s", err)
	}
}

// processPrometheusStats parses the stats into a map of prometheus MetricFamily, filter the stats to only include
// metrics produced by metrics extension (metrics with prefix "envoy_appmesh_").
// Renaming will also happen - we will trim the prefix "envoy_appmesh_".
func processPrometheusStats(statsResponse []byte) (map[string]*dto.MetricFamily, error) {
	metricFamilies, err := parsePrometheusStats(statsResponse)
	if err != nil {
		return nil, fmt.Errorf("error parsing prometheus stats: %s", err)
	}
	filteredMetricFamilies := make(map[string]*dto.MetricFamily)
	for name, metricFamily := range metricFamilies {
		if strings.HasPrefix(name, extendedMetricsPrefix) {
			newStatName := strings.TrimPrefix(name, extendedMetricsPrefix)
			metricFamily.Name = &newStatName
			filteredMetricFamilies[newStatName] = metricFamily
		}
	}
	return filteredMetricFamilies, nil
}

func parsePrometheusStats(statsInput []byte) (map[string]*dto.MetricFamily, error) {
	reader := bytes.NewReader(statsInput)

	var parser expfmt.TextParser
	metricFamilies, err := parser.TextToMetricFamilies(reader)
	if err != nil {
		return nil, err
	}
	return metricFamilies, nil
}

func writeMetricsToResponse(writer http.ResponseWriter, metricFamilies map[string]*dto.MetricFamily) error {
	metricFamiliesSlice := make([]*dto.MetricFamily, 0, len(metricFamilies))
	for _, metricFamily := range metricFamilies {
		metricFamiliesSlice = append(metricFamiliesSlice, metricFamily)
	}

	// We make use of the Gatherers Gather() function to sort the metrics.
	// See https://github.com/prometheus/client_golang/blob/5d584e2717ef525673736d72cd1d12e304f243d7/prometheus/registry.go#L773
	// and https://github.com/prometheus/client_golang/blob/5d584e2717ef525673736d72cd1d12e304f243d7/prometheus/internal/metric.go#L85
	// for more details to understand how it normalize the metrics.
	gatherers := prometheus.Gatherers{
		prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
			return metricFamiliesSlice, nil
		}),
	}
	metricFamiliesSlice, err := gatherers.Gather()
	if err != nil {
		errorMsg := fmt.Sprintf("Error when sorting the metrics, stop writing metrics to response: %v", err)
		log.Error(errorMsg)
		return fmt.Errorf(errorMsg)
	}

	for _, metricFamily := range metricFamiliesSlice {
		// Add newline for each metric family
		io.WriteString(writer, "\n")
		_, err = expfmt.MetricFamilyToText(writer, metricFamily)
		if err != nil {
			return fmt.Errorf("failed to write metric family to response, metric family: %s, error: %v", metricFamily, err)
		}
	}
	return nil
}

// validateGetStatsRequest validates the given http.Request and extract the queryParameters if success.
func validateGetStatsRequest(request *http.Request) (*url.Values, error) {
	// Verify that the request is a GET request
	if request.Method != http.MethodGet {
		errorMsg := fmt.Sprintf("invalid method [%s] in request", request.Method)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	// Verify that no message body is present
	if request.ContentLength > 0 {
		errorMsg := fmt.Sprintf("unexpected content in request. Body size [%d]", request.ContentLength)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	// Verify the parameters supplied
	queryParameters, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		errorMsg := fmt.Sprintf("unable to parse queries in URL: %s", err)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}
	for queryParam, _ := range queryParameters {
		if allowedVal, ok := QuerySet[queryParam]; !ok {
			errorMsg := fmt.Sprintf("unsupported query parameter: %s", queryParam)
			log.Debug(errorMsg)
			return nil, fmt.Errorf(errorMsg)
		} else {
			queryVal := queryParameters.Get(queryParam)
			if allowedVal != nil && allowedVal.(string) != queryVal {
				errorMsg := fmt.Sprintf("unsupported query value for parameter %s: %s, usage: %s", queryParam, queryVal, filterQueryUsage)
				log.Debug(errorMsg)
				return nil, fmt.Errorf(errorMsg)
			}
		}
	}

	// validate for delta
	if queryParameters.Has(deltaQueryKey) {
		if !queryParameters.Has(usedOnlyQueryKey) || !queryParameters.Has(filterQueryKey) {
			errorMsg := fmt.Sprintf("when delta is enabled, both %s and %s query parameters are required", usedOnlyQueryKey, filterQueryKey)
			log.Debug(errorMsg)
			return nil, fmt.Errorf(errorMsg)
		}
	}

	return &queryParameters, nil
}

// constructQueryString constructs the query string for Envoy Admin Stats API.
func constructQueryString(queryParameters url.Values) string {
	queryStringToEnvoy := fmt.Sprintf("%s&%s", config.ENVOY_PROMETHEUS_QUERY_STRING, config.APPMESH_FILTER_STRING)
	if queryParameters.Has(usedOnlyQueryKey) {
		queryStringToEnvoy += fmt.Sprintf("&%s", usedOnlyQueryKey)
	}
	return queryStringToEnvoy
}

// getEnvoyStatsUrl generates the full http url to call Envoy Admin Stats API with the given queryString.
func getEnvoyStatsUrl(agentConfig *config.AgentConfig, queryString string) string {
	return fmt.Sprintf("%s://%s:%d%s%s",
		agentConfig.EnvoyServerScheme,
		agentConfig.EnvoyServerHostName,
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyServerStatsUrl,
		queryString)
}
