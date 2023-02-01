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
	"github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestComputeDeltaForMetricFamily(t *testing.T) {
	// ------------------ Case 1-1 -----------------------
	// Counter type
	input1 := []byte("# TYPE GrpcRequestCount counter\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 0\n")
	input2 := []byte("# TYPE GrpcRequestCount counter\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 5\n")
	// Get metric families to compute delta
	metricFamilies1, err := parsePrometheusStats(input1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies1))
	name := "GrpcRequestCount"
	metricFamily1, ok := metricFamilies1[name]
	assert.True(t, ok)

	metricFamilies2, err := parsePrometheusStats(input2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies2))
	metricFamily2, ok := metricFamilies2[name]
	assert.True(t, ok)

	// Manually call computeDelta
	snapshotter := Snapshotter{}
	delta := make(map[string]*io_prometheus_client.MetricFamily)
	snapshotter.computeDeltaForMetricFamily(metricFamily1, metricFamily2, delta)
	assert.NotNil(t, delta)

	// Examine the delta to make sure it is correctly computed
	deltaMetricFamily, ok := delta[name]
	assert.True(t, ok)
	assert.Equal(t, name, deltaMetricFamily.GetName())
	assert.Equal(t, 1, len(deltaMetricFamily.GetMetric()))
	assert.NotNil(t, deltaMetricFamily.Metric[0].Counter)
	assert.Equal(t, float64(5), deltaMetricFamily.Metric[0].Counter.GetValue())

	// ------------------ Case 1-2 -----------------------
	// Counter type, new metric (with different tag) popping up
	input1 = []byte("# TYPE GrpcRequestCount counter\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 0\n")
	input2 = []byte("# TYPE GrpcRequestCount counter\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http\",VirtualNode=\"client_howto-k8s-http\"} 5\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 3\n")
	// Get metric families to compute delta
	metricFamilies1, err = parsePrometheusStats(input1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies1))
	name = "GrpcRequestCount"
	metricFamily1, ok = metricFamilies1[name]
	assert.True(t, ok)

	metricFamilies2, err = parsePrometheusStats(input2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies2))
	metricFamily2, ok = metricFamilies2[name]
	assert.True(t, ok)

	// Manually call computeDelta
	delta = make(map[string]*io_prometheus_client.MetricFamily)
	snapshotter.computeDeltaForMetricFamily(metricFamily1, metricFamily2, delta)
	assert.NotNil(t, delta)

	// Examine the delta to make sure it is correctly computed
	deltaMetricFamily, ok = delta[name]
	assert.True(t, ok)
	assert.Equal(t, name, deltaMetricFamily.GetName())
	assert.Equal(t, 2, len(deltaMetricFamily.GetMetric()))
	assert.NotNil(t, deltaMetricFamily.Metric[0].Counter)
	assert.Equal(t, float64(5), deltaMetricFamily.Metric[0].Counter.GetValue())
	expectedMetricKey := "Mesh=howto-k8s-http;VirtualNode=client_howto-k8s-http;"
	assert.Equal(t, expectedMetricKey, generateMetricKey(deltaMetricFamily.Metric[0].GetLabel()))
	assert.Equal(t, float64(3), deltaMetricFamily.Metric[1].Counter.GetValue())
	expectedMetricKey = "Mesh=howto-k8s-http2;VirtualNode=client_howto-k8s-http2;"
	assert.Equal(t, expectedMetricKey, generateMetricKey(deltaMetricFamily.Metric[1].GetLabel()))

	// ------------------ Case 2 -----------------------
	// Histogram Type
	input1 = []byte("# TYPE TargetResponseTime histogram\n" +
		"TargetResponseTime_bucket{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\",le=\"0.5\"} 1\n" +
		"TargetResponseTime_bucket{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\",le=\"+Inf\"} 1\n" +
		"TargetResponseTime_sum{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\"} 1.0\n" +
		"TargetResponseTime_count{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\"} 1\n")

	input2 = []byte("# TYPE TargetResponseTime histogram\n" +
		"TargetResponseTime_bucket{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\",le=\"0.5\"} 3\n" +
		"TargetResponseTime_bucket{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\",le=\"+Inf\"} 3\n" +
		"TargetResponseTime_sum{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\"} 13.5\n" +
		"TargetResponseTime_count{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\"} 3\n")

	// Get metric families to compute delta
	name = "TargetResponseTime"
	metricFamilies1, err = parsePrometheusStats(input1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies1))
	metricFamily1, ok = metricFamilies1[name]
	assert.True(t, ok)

	metricFamilies2, err = parsePrometheusStats(input2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies2))
	metricFamily2, ok = metricFamilies2[name]
	assert.True(t, ok)

	// Compute Delta
	delta = make(map[string]*io_prometheus_client.MetricFamily)
	snapshotter.computeDeltaForMetricFamily(metricFamily1, metricFamily2, delta)

	assert.NotNil(t, delta)
	deltaMetricFamily, ok = delta[name]
	assert.True(t, ok)

	// Examine the delta to make sure it is correctly computed
	assert.Equal(t, name, deltaMetricFamily.GetName())
	assert.Equal(t, 1, len(deltaMetricFamily.GetMetric()))
	assert.Nil(t, deltaMetricFamily.Metric[0].Counter)
	assert.NotNil(t, deltaMetricFamily.Metric[0].Histogram)
	assert.Equal(t, 2, len(deltaMetricFamily.Metric[0].Histogram.GetBucket()))
	assert.Equal(t, uint64(2), deltaMetricFamily.Metric[0].Histogram.Bucket[0].GetCumulativeCount())
	assert.Equal(t, 12.5, deltaMetricFamily.Metric[0].Histogram.GetSampleSum())
	assert.Equal(t, uint64(2), deltaMetricFamily.Metric[0].Histogram.GetSampleCount())

	expectedDeltaPrint := "# TYPE TargetResponseTime histogram\n" +
		"TargetResponseTime_bucket{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\",le=\"0.5\"} 2\n" +
		"TargetResponseTime_bucket{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\",le=\"+Inf\"} 2\n" +
		"TargetResponseTime_sum{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\"} 12.5\n" +
		"TargetResponseTime_count{appmesh_mesh=\"mesh-mmo412fg-iggnyj9z\",appmesh_virtual_node=\"frontend-mmo412fg-iggnyj9z\"} 2\n"
	writer := new(strings.Builder)
	_, err = expfmt.MetricFamilyToText(writer, deltaMetricFamily)
	assert.NoError(t, err)
	assert.Equal(t, expectedDeltaPrint, writer.String())

	// ------------------ Case 3 -----------------------
	// Gauge Type (Should not compute delta)
	input1 = []byte("# TYPE TestGaugeMetric gauge\n" +
		"TestGaugeMetric{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 1\n")
	input2 = []byte("# TYPE TestGaugeMetric gauge\n" +
		"TestGaugeMetric{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 5\n")
	// Get metric families to compute delta
	metricFamilies1, err = parsePrometheusStats(input1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies1))
	name = "TestGaugeMetric"
	metricFamily1, ok = metricFamilies1[name]
	assert.True(t, ok)

	metricFamilies2, err = parsePrometheusStats(input2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies2))
	metricFamily2, ok = metricFamilies2[name]
	assert.True(t, ok)

	// Manually call computeDelta
	delta = make(map[string]*io_prometheus_client.MetricFamily)
	snapshotter.computeDeltaForMetricFamily(metricFamily1, metricFamily2, delta)
	assert.NotNil(t, delta)

	// Examine the delta to make sure it is correctly computed
	deltaMetricFamily, ok = delta[name]
	assert.True(t, ok)
	assert.Equal(t, name, deltaMetricFamily.GetName())
	assert.Equal(t, 1, len(deltaMetricFamily.GetMetric()))
	assert.NotNil(t, deltaMetricFamily.Metric[0].Gauge)
	assert.Equal(t, float64(5), deltaMetricFamily.Metric[0].Gauge.GetValue())
}
