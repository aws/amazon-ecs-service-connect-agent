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

package snapshot

import (
	"sync"
	"testing"

	"github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func makeMetricFamily(name string, value float64) map[string]*io_prometheus_client.MetricFamily {
	metricName := name
	metricType := io_prometheus_client.MetricType_COUNTER
	return map[string]*io_prometheus_client.MetricFamily{
		name: {
			Name: &metricName,
			Type: &metricType,
			Metric: []*io_prometheus_client.Metric{
				{Counter: &io_prometheus_client.Counter{Value: proto.Float64(value)}},
			},
		},
	}
}

func TestGetSetSnapshot(t *testing.T) {
	snapshotter := Snapshotter{}
	assert.Nil(t, snapshotter.GetSnapshot())

	snapshot := makeMetricFamily("RequestCount", 10)
	snapshotter.SetSnapshot(snapshot)
	assert.Equal(t, snapshot, snapshotter.GetSnapshot())
}

func TestGetSetDelta(t *testing.T) {
	snapshotter := Snapshotter{}
	assert.Nil(t, snapshotter.GetDelta())

	delta := makeMetricFamily("RequestCount", 5)
	snapshotter.SetDelta(delta)
	assert.Equal(t, delta, snapshotter.GetDelta())
}

func TestResetSnapshot(t *testing.T) {
	snapshotter := Snapshotter{}

	snapshot := makeMetricFamily("RequestCount", 10)
	snapshotter.SetSnapshot(snapshot)
	assert.NotNil(t, snapshotter.GetSnapshot())

	snapshotter.ResetSnapshot()
	assert.Nil(t, snapshotter.GetSnapshot())
}

func TestConcurrentReadWrite(t *testing.T) {
	snapshotter := Snapshotter{}
	var waitGroup sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 10; i++ {
		waitGroup.Add(1)
		go func(val float64) {
			defer waitGroup.Done()
			snapshotter.SetSnapshot(makeMetricFamily("RequestCount", val))
			snapshotter.SetDelta(makeMetricFamily("RequestCount", val))
		}(float64(i))
	}

	// Concurrent readers that verify returned values are complete and valid
	for i := 0; i < 10; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if snap := snapshotter.GetSnapshot(); snap != nil {
				metricFamily := snap["RequestCount"]
				assert.NotNil(t, metricFamily)
				assert.NotNil(t, metricFamily.Name)
				assert.Equal(t, "RequestCount", metricFamily.GetName())
				assert.Equal(t, 1, len(metricFamily.Metric))
				assert.NotNil(t, metricFamily.Metric[0].Counter)
				val := metricFamily.Metric[0].Counter.GetValue()
				assert.True(t, val >= 0 && val <= 9, "snapshot counter should be between 0 and 9, got %f", val)
			}
			if delta := snapshotter.GetDelta(); delta != nil {
				metricFamily := delta["RequestCount"]
				assert.NotNil(t, metricFamily)
				assert.NotNil(t, metricFamily.Name)
				assert.Equal(t, "RequestCount", metricFamily.GetName())
				assert.Equal(t, 1, len(metricFamily.Metric))
				assert.NotNil(t, metricFamily.Metric[0].Counter)
				val := metricFamily.Metric[0].Counter.GetValue()
				assert.True(t, val >= 0 && val <= 9, "delta counter should be between 0 and 9, got %f", val)
			}
		}()
	}

	waitGroup.Wait()

	// After all goroutines finish, both snapshot and delta must be non-nil and hold valid values
	snap := snapshotter.GetSnapshot()
	assert.NotNil(t, snap)
	snapVal := snap["RequestCount"].Metric[0].Counter.GetValue()
	assert.True(t, snapVal >= 0 && snapVal <= 9, "final snapshot counter should be between 0 and 9, got %f", snapVal)

	delta := snapshotter.GetDelta()
	assert.NotNil(t, delta)
	deltaVal := delta["RequestCount"].Metric[0].Counter.GetValue()
	assert.True(t, deltaVal >= 0 && deltaVal <= 9, "final delta counter should be between 0 and 9, got %f", deltaVal)
}

func TestConcurrentReset(t *testing.T) {
	snapshotter := Snapshotter{}
	var waitGroup sync.WaitGroup

	// Set an initial snapshot
	snapshotter.SetSnapshot(makeMetricFamily("RequestCount", 100))
	snapshotter.SetDelta(makeMetricFamily("RequestCount", 50))

	// Concurrent resets
	for i := 0; i < 10; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			snapshotter.ResetSnapshot()
		}()
	}

	waitGroup.Wait()

	// After all resets, snapshot must be nil
	assert.Nil(t, snapshotter.GetSnapshot())
	// Delta should be unaffected by ResetSnapshot
	assert.NotNil(t, snapshotter.GetDelta())
	assert.Equal(t, float64(50), snapshotter.GetDelta()["RequestCount"].Metric[0].Counter.GetValue())

	// Set a new snapshot after reset and verify it's not contaminated by the old value
	snapshotter.SetSnapshot(makeMetricFamily("RequestCount", 5))
	assert.Equal(t, float64(5), snapshotter.GetSnapshot()["RequestCount"].Metric[0].Counter.GetValue())
}
