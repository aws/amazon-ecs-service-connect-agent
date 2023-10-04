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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/client"
	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"

	log "github.com/sirupsen/logrus"
	gjson "github.com/tidwall/gjson"
	rate "golang.org/x/time/rate"
)

const (
	Healthy           = "HEALTHY"
	Unhealthy         = "UNHEALTHY"
	UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
	UPDATE_FAILED     = "UPDATE_FAILED"
	NOT_INITIALIZED   = "NOT_INITIALIZED"
	INITIALIZED       = "INITIALIZED"
	LIVE              = "LIVE"
)

const (
	connected                    = "CONNECTED"
	notConnected                 = "NOT_CONNECTED"
	healthCheckHttpClientTimeout = 2 * time.Second
)

type HealthStatus struct {
	HealthStatus                          string      `json:"healthStatus"`
	AgentUptime                           string      `json:"agentUptime"`
	EnvoyPid                              string      `json:"envoyPid"`
	EnvoyState                            string      `json:"envoyState"`
	EnvoyRestartCount                     string      `json:"envoyRestartCount"`
	ManagementServerConnectionStatus      string      `json:"managementServerConnectionStatus,omitempty"`
	ManagementServerDisconnectedTimestamp *time.Time  `json:"managementServerDisconnectedTimestamp,omitempty"`
	EnvoyReadinessState                   string      `json:"envoyReadinessState"`
	InitialConfigUpdateStatus             string      `json:"initialConfigUpdateStatus,omitempty"`
	LastConnectionStatus                  string      `json:"lastConnectionStatus,omitempty"` //Represents the last ManagementServerConnectionStatus
	FlipTimestamps                        []time.Time `json:"FlipTimestamps,omitempty"`       //Denotes the times when the connection status has flipped
}

type HealthStatusHandler struct {
	HealthStatus *HealthStatus
	Limiter      *rate.Limiter
}

func (healthStatusHandler *HealthStatusHandler) EnvoyStatus(response http.ResponseWriter, request *http.Request) {

	if !healthStatusHandler.Limiter.Allow() {
		responseCode := http.StatusTooManyRequests
		http.Error(response, http.StatusText(responseCode), responseCode)
		return
	}

	responseBody, _ := json.MarshalIndent(&healthStatusHandler.HealthStatus, "", "  ")
	response.WriteHeader(http.StatusOK)
	_, err := io.WriteString(response, string(responseBody))
	if err != nil {
		log.Error("Error while returning response")
	}
}

type EnvoyEndpointHttpData struct {
	client         *http.Client
	readyReq       *http.Request
	statsReq       *http.Request
	agentStartTime time.Time
}

func (healthStatus *HealthStatus) computeHealthStatus(
	pollData *EnvoyEndpointHttpData,
	messageSources *messagesources.MessageSources,
	agentConfig config.AgentConfig) {

	healthStatus.AgentUptime = fmt.Sprintf("%.fs", time.Since(pollData.agentStartTime).Seconds())
	healthStatus.EnvoyPid = strconv.Itoa(messageSources.GetPid())
	healthStatus.EnvoyRestartCount = strconv.Itoa(messageSources.GetProcessRestartCount())

	// Get readiness response from '/ready' endpoint of Envoy admin interface
	// https://www.envoyproxy.io/docs/envoy/latest/operations/admin#get--ready
	// Should output a string and error code reflecting the state of the server.
	// 200 is returned for the LIVE state, and 503 otherwise.
	response, err := pollData.client.Do(pollData.readyReq)
	if err != nil {
		log.Error("Envoy readiness check failed with: ", err)
		healthStatus.EnvoyState = "UNREACHABLE"
	}

	if response != nil {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Warn("Envoy readiness check failed to read response with: ", err)
		}
		healthStatus.EnvoyState = strings.TrimSpace(string(responseBody))
		log.Debugf("Envoy readiness check status %d, %s",
			response.StatusCode, healthStatus.EnvoyState)
		response.Body.Close()
	}

	response, err = pollData.client.Do(pollData.statsReq)
	if err != nil {
		log.Error("Envoy connectivity check failed with: ", err)
	}
	if response != nil {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Warn("Envoy connectivity check failed to read response with: ", err)
		}
		if !agentConfig.EnableRelayModeForXds {
			// Get `control_plane.connected_state` from Envoy admin interface
			log.Debugf("Envoy connectivity check status %d, %s",
				response.StatusCode, string(responseBody))
			healthStatus.computeManagementServerConnectionStatus(string(responseBody))
		}
		healthStatus.computeEnvoyReadinessState(string(responseBody))
		response.Body.Close()
	}

	healthStatus.computeHealthCheck(agentConfig)
}

func (healthStatus *HealthStatus) computeManagementServerConnectionStatus(responseString string) {
	// A boolean (1 for connected/true and 0 for disconnected/false) that indicates the
	// current connection state with management server.
	// Ref: https://www.envoyproxy.io/docs/envoy/latest/configuration/overview/mgmt_server
	envoyControlPlaneConnectedStateValue := gjson.Get(responseString, `stats.#(name="control_plane.connected_state").value`).String()

	updatedManagementServerConnectionStatus := notConnected
	if envoyControlPlaneConnectedStateValue == "1" {
		updatedManagementServerConnectionStatus = connected
	}

	if healthStatus.ManagementServerConnectionStatus != updatedManagementServerConnectionStatus {
		log.Debugf("Control Plane connection state changed to: %s\n", updatedManagementServerConnectionStatus)
		switch updatedManagementServerConnectionStatus {
		case notConnected:
			disconnectedTimestamp := time.Now()
			healthStatus.ManagementServerDisconnectedTimestamp = &disconnectedTimestamp
		case connected:
			// Once Envoy is connected again, clear this timestamp, so it is omitted in the response
			healthStatus.ManagementServerDisconnectedTimestamp = nil
		}
		healthStatus.ManagementServerConnectionStatus = updatedManagementServerConnectionStatus
	}
}

func (healthStatus *HealthStatus) computeEnvoyReadinessState(responseString string) {
	if healthStatus.EnvoyReadinessState == NOT_INITIALIZED &&
		healthStatus.EnvoyState == LIVE {
		// This is the first time Envoy has initialized with the static/dynamic configuration.
		// In this case, we need to check whether the Envoy has successfully loaded the configuration.
		// Based on Envoy docs, https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/init
		// The server waits for a bounded period of time for at least one response (or failure) for LDS/RDS requests.
		// So, when the initial config is failed to be created by Envoy
		// (Example: port conflicts, lacking permissions to bind to port), we want to mark Envoy as Unhealthy.
		// Here, we check for the listener manager stats to find listener creation failures.
		healthStatus.InitialConfigUpdateStatus = UPDATE_SUCCESSFUL
		listenerManagerFailureStats := gjson.Get(responseString, `stats.#(name="listener_manager.listener_create_failure").value`)
		if listenerManagerFailureStats.Exists() {
			listenerManagerFailureStatsValue := listenerManagerFailureStats.Int()
			if listenerManagerFailureStatsValue > 0 {
				log.Debugf("Listener manager failed to update %d listeners \n", listenerManagerFailureStatsValue)
				healthStatus.InitialConfigUpdateStatus = UPDATE_FAILED
			}
		}
		//TODO: Check for cluster creation failures.
		healthStatus.EnvoyReadinessState = INITIALIZED
	}
}

func (healthStatus *HealthStatus) computeHealthCheck(agentConfig config.AgentConfig) {
	// If Envoy is not in LIVE state (not initialized or not ready), it is reported as Unhealthy.
	// If Envoy is initialized but if there are failures in the initial config creation (leading to partial resources creation),
	// it is reported as Unhealthy.
	// Disconnection from Control plane (Applicable only when not using Relay Mode):
	// - Even when initialized, Envoy is statically stable and hence continue to report healthy.
    // - If the connection status is CONNECTED, Envoy is reported as Healthy, and FlipTimestamps is reset.
    // - If the connection status is NOT CONNECTED and has changed since the last check,
    //   the current time is appended to FlipTimestamps, provided that the timestamp is within the last 30 minutes.
    // - If the length of FlipTimestamps reaches or exceeds a predefined threshold of 10, Envoy is reported as Unhealthy.
    //   Otherwise, it is reported as Healthy.

    currentTime := time.Now()

    // If LastConnectionStatus is empty, initialize it with the value of ManagementServerConnectionStatus.
    if healthStatus.LastConnectionStatus == "" {
        healthStatus.LastConnectionStatus = healthStatus.ManagementServerConnectionStatus
    }

	switch healthStatus.EnvoyState {
	case LIVE:
		if healthStatus.InitialConfigUpdateStatus == UPDATE_FAILED {
			healthStatus.HealthStatus = Unhealthy
			break
		}
		if agentConfig.EnableRelayModeForXds {
			healthStatus.HealthStatus = Healthy
			break
		}

    // If ManagementServerConnectionStatus has changed since the last update, add the current time to FlipTimestamps.
        if healthStatus.ManagementServerConnectionStatus != healthStatus.LastConnectionStatus {
            healthStatus.FlipTimestamps = append(healthStatus.FlipTimestamps, currentTime)

            // Remove timestamps older than 30 minutes from FlipTimestamps.
            thirtyMinutesAgo := currentTime.Add(-30 * time.Minute)
            count := 0
            for i, timestamp := range healthStatus.FlipTimestamps {
                if timestamp.After(thirtyMinutesAgo) {
                    break
                }
                count = i + 1
            }
            healthStatus.FlipTimestamps = healthStatus.FlipTimestamps[count:]

            // Update LastConnectionStatus with the current ManagementServerConnectionStatus.
            healthStatus.LastConnectionStatus = healthStatus.ManagementServerConnectionStatus
        }

		if len(healthStatus.FlipTimestamps) >= 10 {
			healthStatus.HealthStatus = Unhealthy
		} else {
			healthStatus.HealthStatus = Healthy
		}

	default:
		healthStatus.HealthStatus = Unhealthy
	}
}

func (healthStatus *HealthStatus) StartHealthCheck(
	agentStartTime time.Time,
	agentConfig config.AgentConfig,
	messageSources *messagesources.MessageSources) {

	var envoyEndPointData EnvoyEndpointHttpData

	// Create a basic http client, we are polling health check routinely at a pretty short interval, so there
	// is no need to use retryable client here.
	httpClient, err := client.CreateDefaultHttpClientForEnvoyServer(agentConfig)
	if err != nil {
		log.Errorf("unable to create a default Http Client: %v", err)
		return
	}

	// Ease the timeout to 2s for ready request and stats request for health check.
	httpClient.Timeout = healthCheckHttpClientTimeout
	envoyEndPointData.client = httpClient

	var envoyAddress = fmt.Sprintf("%s://%s", agentConfig.EnvoyServerScheme, agentConfig.EnvoyServerHostName)
	var filterQueryString = "filter=control_plane.connected_state&format=json"
	var readyUrl = fmt.Sprintf("%s:%d%s",
		envoyAddress,
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyReadyUrl)
	var statsUrl = fmt.Sprintf("%s:%d%s?%s",
		envoyAddress,
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyServerStatsUrl,
		filterQueryString)

	envoyEndPointData.readyReq, _ = client.CreateStandardAgentHttpRequest(http.MethodGet, readyUrl, nil)
	envoyEndPointData.statsReq, _ = client.CreateStandardAgentHttpRequest(http.MethodGet, statsUrl, nil)

	envoyEndPointData.agentStartTime = agentStartTime
	healthStatus.EnvoyReadinessState = NOT_INITIALIZED

	// Poll Envoy health once every 5 Envoy PID poll
	// Add Jitter between 10ms - 50ms
	jitter := time.Duration(rand.Intn(40)+10) * time.Millisecond
	ticker := time.NewTicker(agentConfig.HcPollInterval + jitter)
	defer ticker.Stop()

	// Loop forever
	for {
		select {
		case <-ticker.C:
			healthStatus.computeHealthStatus(&envoyEndPointData, messageSources, agentConfig)
		case <-messageSources.BlockingEnvoyStatusTrigger:
			healthStatus.computeHealthStatus(&envoyEndPointData, messageSources, agentConfig)
		}
	}
}
