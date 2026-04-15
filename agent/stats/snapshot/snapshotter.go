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

	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
)

type Snapshotter struct {
	snapshot    map[string]*io_prometheus_client.MetricFamily
	delta       map[string]*io_prometheus_client.MetricFamily
	mutex       sync.RWMutex
	HttpClient  *retryablehttp.Client
	HttpRequest *retryablehttp.Request
}

func (snapshotter *Snapshotter) GetSnapshot() map[string]*io_prometheus_client.MetricFamily {
	snapshotter.mutex.RLock()
	defer snapshotter.mutex.RUnlock()
	return snapshotter.snapshot
}

func (snapshotter *Snapshotter) SetSnapshot(snapshot map[string]*io_prometheus_client.MetricFamily) {
	snapshotter.mutex.Lock()
	defer snapshotter.mutex.Unlock()
	snapshotter.snapshot = snapshot
}

// ResetSnapshot clears the previous snapshot so the next delta computation treats
// the next snapshot as the first one.
func (snapshotter *Snapshotter) ResetSnapshot() {
	snapshotter.SetSnapshot(nil)
	log.Info("Snapshot reset due to Envoy process exit.")
}

func (snapshotter *Snapshotter) GetDelta() map[string]*io_prometheus_client.MetricFamily {
	snapshotter.mutex.RLock()
	defer snapshotter.mutex.RUnlock()
	return snapshotter.delta
}

func (snapshotter *Snapshotter) SetDelta(delta map[string]*io_prometheus_client.MetricFamily) {
	snapshotter.mutex.Lock()
	defer snapshotter.mutex.Unlock()
	snapshotter.delta = delta
}
