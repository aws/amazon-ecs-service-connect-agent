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

package healthcheck

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"

	"github.com/stretchr/testify/assert"
	gjson "github.com/tidwall/gjson"
	rate "golang.org/x/time/rate"
)

func TestHealthCheckServerHandler(t *testing.T) {
	healthStatus := HealthStatus{
		EnvoyState:                 "LIVE",
		ManagementServerConnection: "true",
		ServerInfo: ServerInfo{
			Version:       "1",
			CurrentUptime: "123",
			TotalUptime:   "456",
			ResourceArn:   "mesh/testMesh/virtualNode/testVirtualNode",
		},
	}
	healthStatusHandler := HealthStatusHandler{
		HealthStatus: &healthStatus,
		Limiter:      rate.NewLimiter(config.TPS_LIMIT, config.BURST_TPS_LIMIT),
	}

	srv := httptest.NewServer(http.HandlerFunc(healthStatusHandler.EnvoyStatus))
	defer srv.Close()

	res, _ := http.Get(srv.URL)
	defer res.Body.Close()

	respBody, _ := ioutil.ReadAll(res.Body)
	respString := string(respBody)

	assert.Equal(t, "LIVE", gjson.Get(respString, "envoyState").String())
	assert.Equal(t, "true", gjson.Get(respString, "managementServerConnection").String())
	assert.Equal(t, "1", gjson.Get(respString, "serverInfo.version").String())
	assert.Equal(t, "123", gjson.Get(respString, "serverInfo.currentUptime").String())
	assert.Equal(t, "456", gjson.Get(respString, "serverInfo.totalUptime").String())
	assert.Equal(t, "mesh/testMesh/virtualNode/testVirtualNode", gjson.Get(respString, "serverInfo.resourceArn").String())
}

func TestHealthUpdater(t *testing.T) {
	var healthStatus HealthStatus
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()

	mux := http.NewServeMux()
	serverInfoResponse := `{ "state": "LIVE", "node": { "id": "mesh/testMesh/virtualNode/testVirtualNode" }, "version": "1", "uptime_current_epoch": "123", "uptime_all_epochs": "456" }`
	mux.HandleFunc(agentConfig.EnvoyServerInfoUrl, func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(res, serverInfoResponse)
	})

	statsResponse := `{ "stats": [ { "name": "control_plane.connected_state", "value": 1 } ] }`
	mux.HandleFunc(agentConfig.EnvoyServerStatsUrl, func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(res, statsResponse)
	})

	srv := httptest.NewUnstartedServer(mux)
	defer srv.Close()

	// Create a new listener to listen om Envoy Admin Port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", agentConfig.EnvoyServerAdminPort))
	assert.Nil(t, err)

	// Close the httptest listener as it listens on port 80 by default
	err = srv.Listener.Close()
	assert.Nil(t, err)

	// Attach the new listener to the httptest server
	srv.Listener = listener
	srv.Start()

	var messageSources messagesources.MessageSources
	messageSources.SetupChannels()

	// Emulate the agent polling the Envoy process and writing the process data to the channels
	agentTicker := time.NewTicker(100 * time.Millisecond)
	defer agentTicker.Stop()

	done := make(chan bool)
	defer close(done)

	go func() {
		for {
			select {
			case <-agentTicker.C:
				messageSources.SetPid(21)
				messageSources.SetProcessRestartCount(3)
				messageSources.SetProcessState(true)
			case <-done:
				return
			}
		}
	}()

	start := time.Now()
	go healthStatus.StartHealthCheck(start, agentConfig, &messageSources)

	// Wait for 5 seconds
	time.Sleep(5 * time.Second)
	minAgentUptime := 4.00
	agentUptime, _ := strconv.ParseFloat(healthStatus.AgentUptime[:len(healthStatus.AgentUptime)-1], 64)
	// Assert agent has been up for about 5 seconds
	assert.GreaterOrEqual(t, agentUptime, minAgentUptime)

	assert.Equal(t, "21", healthStatus.EnvoyPid)
	assert.Equal(t, "3", healthStatus.EnvoyRestartCount)
	assert.Equal(t, "LIVE", healthStatus.EnvoyState)
	assert.Equal(t, "true", healthStatus.ManagementServerConnection)
	assert.Equal(t, "1", healthStatus.ServerInfo.Version)
	assert.Equal(t, "123", healthStatus.ServerInfo.CurrentUptime)
	assert.Equal(t, "456", healthStatus.ServerInfo.TotalUptime)
	assert.Equal(t, "mesh/testMesh/virtualNode/testVirtualNode", healthStatus.ServerInfo.ResourceArn)
}
