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
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/internal/netlistenertest"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"

	"github.com/stretchr/testify/assert"
	gjson "github.com/tidwall/gjson"
	rate "golang.org/x/time/rate"
)

func TestHealthCheckServerHandler(t *testing.T) {
	statusSinceTime := time.Now()
	healthStatus := HealthStatus{
		HealthStatus:                          "HEALTHY",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
		EnvoyReadinessState:                   "INITIALIZED",
		InitialConfigUpdateStatus:             "UPDATE_SUCCESSFUL",
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

	assert.Equal(t, "HEALTHY", gjson.Get(respString, "healthStatus").String())
	assert.Equal(t, "LIVE", gjson.Get(respString, "envoyState").String())
	assert.Equal(t, "LIVE", gjson.Get(respString, "localRelayEnvoyState").String())
	assert.Equal(t, "CONNECTED", gjson.Get(respString, "managementServerConnectionStatus").String())
	assert.Equal(t, "INITIALIZED", gjson.Get(respString, "envoyReadinessState").String())
	assert.Equal(t, "UPDATE_SUCCESSFUL", gjson.Get(respString, "initialConfigUpdateStatus").String())
}

func TestHealthUpdater(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "tcp")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "0")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")

	os.Setenv("HC_POLL_INTERVAL_MS", "2000")
	defer os.Unsetenv("HC_POLL_INTERVAL_MS")
	var healthStatus HealthStatus
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()

	// Enable local relay mode
	agentConfig.EnableLocalRelayModeForXds = true

	mux := http.NewServeMux()
	readyResponse := "LIVE"
	mux.HandleFunc(agentConfig.EnvoyReadyUrl, func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(res, readyResponse)
	})

	statsResponse := `{ "stats": [ { "name": "control_plane.connected_state", "value": 1 } ] }`
	mux.HandleFunc(agentConfig.EnvoyServerStatsUrl, func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(res, statsResponse)
	})

	srv := httptest.NewUnstartedServer(mux)
	defer srv.Close()

	// Create a new listener to listen on Envoy Admin Port
	var envoyListenCtx netlistenertest.ListenContext
	err := envoyListenCtx.CreateEnvoyAdminListener(&agentConfig)
	assert.Nil(t, err)
	defer envoyListenCtx.Close()

	// Close the httptest listener as it listens on port 80 by default
	err = srv.Listener.Close()
	assert.Nil(t, err)

	// Attach the new listener to the httptest server
	srv.Listener = *envoyListenCtx.Listener
	srv.Start()

	srv2 := httptest.NewUnstartedServer(mux)
	defer srv2.Close()

	// Create a new listener to listen on Local Relay Envoy Admin Port
	var localRelayEnvoyListenCtx netlistenertest.ListenContext
	// Create a new listener to listen on Local Relay Envoy Admin Port
	err = localRelayEnvoyListenCtx.CreateLocalRelayEnvoyAdminListener(&agentConfig)
	assert.Nil(t, err)
	defer localRelayEnvoyListenCtx.Close()

	// Close the httptest listener as it listens on port 80 by default
	err = srv2.Listener.Close()
	assert.Nil(t, err)

	// Attach the new listener to the httptest server
	srv2.Listener = *localRelayEnvoyListenCtx.Listener
	srv2.Start()

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
	assert.Equal(t, "HEALTHY", healthStatus.HealthStatus)
	assert.Equal(t, "LIVE", healthStatus.EnvoyState)
	assert.Equal(t, "LIVE", healthStatus.LocalRelayEnvoyState)
	assert.Equal(t, "CONNECTED", healthStatus.ManagementServerConnectionStatus)
}

func TestComputeHealthCheck_LocalRelayEnvoyUnreachable_Unhealthy(t *testing.T) {
	statusSinceTime := time.Now()
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "UNREACHABLE",
		ManagementServerConnectionStatus:      "CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "UNHEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_EnvoyLive_Healthy(t *testing.T) {
	statusSinceTime := time.Now()
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "HEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_EnvoyUnreachable_UnHealthy(t *testing.T) {
	statusSinceTime := time.Now()
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "UNREACHABLE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "UNHEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_EnvoyUnInitialized_UnHealthy(t *testing.T) {
	statusSinceTime := time.Now()
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "INITIALIZING",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "UNHEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_EnvoyDisconnected_Healthy(t *testing.T) {
	statusSinceTime := time.Now().Add(-time.Minute * 30)
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "NOT_CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "HEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_EnvoyDisconnected_UnHealthy(t *testing.T) {
	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "0")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")
	statusSinceTime := time.Now().Add(-time.Hour * 24 * 30)
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "NOT_CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "UNHEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_EnvoyDisconnected_RelayMode_Healthy(t *testing.T) {
	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "1")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")
	statusSinceTime := time.Now().Add(-time.Hour * 24 * 30)
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "NOT_CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "HEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_InitialConfigUpdateFailed(t *testing.T) {
	statusSinceTime := time.Now().Add(-time.Hour * 24 * 30)
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
		InitialConfigUpdateStatus:             "UPDATE_FAILED",
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "UNHEALTHY", healthStatus.HealthStatus)
}

func TestComputeHealthCheck_InitialConfigUpdateSuccessful(t *testing.T) {
	statusSinceTime := time.Now().Add(-time.Hour * 24 * 30)
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
		InitialConfigUpdateStatus:             "UPDATE_SUCCESSFUL",
	}
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnableLocalRelayModeForXds = true

	healthStatus.computeHealthCheck(agentConfig)

	assert.Equal(t, "HEALTHY", healthStatus.HealthStatus)
}

func TestComputeEnvoyReadinessState_NoFailedStats(t *testing.T) {
	responseString := "{\"stats\":[{\"name\":\"control_plane.connected_state\",\"value\":0}]}"
	healthStatus := HealthStatus{
		HealthStatus:                     "",
		EnvoyState:                       "LIVE",
		LocalRelayEnvoyState:             "LIVE",
		ManagementServerConnectionStatus: "CONNECTED",
		EnvoyReadinessState:              "NOT_INITIALIZED",
	}
	healthStatus.computeEnvoyReadinessState(responseString)
	assert.Equal(t, "UPDATE_SUCCESSFUL", healthStatus.InitialConfigUpdateStatus)
	assert.Equal(t, "INITIALIZED", healthStatus.EnvoyReadinessState)
}

func TestComputeEnvoyReadinessState_ZeroFailedStats(t *testing.T) {
	responseString := "{\"stats\":[{\"name\":\"listener_manager.listener_create_failure\",\"value\":0}]}"
	healthStatus := HealthStatus{
		HealthStatus:                     "",
		EnvoyState:                       "LIVE",
		LocalRelayEnvoyState:             "LIVE",
		ManagementServerConnectionStatus: "CONNECTED",
		EnvoyReadinessState:              "NOT_INITIALIZED",
	}
	healthStatus.computeEnvoyReadinessState(responseString)
	assert.Equal(t, "UPDATE_SUCCESSFUL", healthStatus.InitialConfigUpdateStatus)
	assert.Equal(t, "INITIALIZED", healthStatus.EnvoyReadinessState)
}

func TestComputeEnvoyReadinessState_FailedStats(t *testing.T) {
	responseString := "{\"stats\":[{\"name\":\"listener_manager.listener_create_failure\",\"value\":3}]}"
	healthStatus := HealthStatus{
		HealthStatus:                     "",
		EnvoyState:                       "LIVE",
		LocalRelayEnvoyState:             "LIVE",
		ManagementServerConnectionStatus: "CONNECTED",
		EnvoyReadinessState:              "NOT_INITIALIZED",
	}
	healthStatus.computeEnvoyReadinessState(responseString)
	assert.Equal(t, "UPDATE_FAILED", healthStatus.InitialConfigUpdateStatus)
	assert.Equal(t, "INITIALIZED", healthStatus.EnvoyReadinessState)
}

func TestComputeEnvoyReadinessState_FailedStats_AfterInitialization(t *testing.T) {
	responseString := "{\"stats\":[{\"name\":\"listener_manager.listener_create_failure\",\"value\":3}]}"
	healthStatus := HealthStatus{
		HealthStatus:                     "",
		EnvoyState:                       "LIVE",
		LocalRelayEnvoyState:             "LIVE",
		ManagementServerConnectionStatus: "CONNECTED",
		EnvoyReadinessState:              "INITIALIZED",
		InitialConfigUpdateStatus:        "UPDATE_SUCCESSFUL",
	}
	healthStatus.computeEnvoyReadinessState(responseString)
	assert.Equal(t, "UPDATE_SUCCESSFUL", healthStatus.InitialConfigUpdateStatus)
	assert.Equal(t, "INITIALIZED", healthStatus.EnvoyReadinessState)
}

func TestComputeManagementServerConnectionStatus_EnvoyDisconnected(t *testing.T) {
	responseString := "{\"stats\":[{\"name\":\"control_plane.connected_state\",\"value\":0}]}"

	startTime := time.Now()
	healthStatus := HealthStatus{
		HealthStatus:                     "",
		EnvoyState:                       "LIVE",
		LocalRelayEnvoyState:             "LIVE",
		ManagementServerConnectionStatus: "CONNECTED",
	}

	healthStatus.computeManagementServerConnectionStatus(responseString)

	actualDisconnectedTimestamp := *healthStatus.ManagementServerDisconnectedTimestamp
	assert.Equal(t, "NOT_CONNECTED", healthStatus.ManagementServerConnectionStatus)
	// Verify that the disconnected timestamp is set and recent
	assert.True(t, actualDisconnectedTimestamp.After(startTime))
}

func TestComputeManagementServerConnectionStatus_EnvoyConnected(t *testing.T) {
	responseString := "{\"stats\":[{\"name\":\"control_plane.connected_state\",\"value\":1}]}"

	statusSinceTime := time.Now()
	healthStatus := HealthStatus{
		HealthStatus:                          "",
		EnvoyState:                            "LIVE",
		LocalRelayEnvoyState:                  "LIVE",
		ManagementServerConnectionStatus:      "NOT_CONNECTED",
		ManagementServerDisconnectedTimestamp: &statusSinceTime,
	}

	healthStatus.computeManagementServerConnectionStatus(responseString)

	assert.Equal(t, "CONNECTED", healthStatus.ManagementServerConnectionStatus)
	assert.True(t, healthStatus.ManagementServerDisconnectedTimestamp == nil)
}
