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
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
	log "github.com/sirupsen/logrus"
	gjson "github.com/tidwall/gjson"
	rate "golang.org/x/time/rate"
)

type ServerInfo struct {
	Version       string `json:"version"`
	TotalUptime   string `json:"totalUptime"`
	CurrentUptime string `json:"currentUptime"`
	ResourceArn   string `json:"resourceArn"`
}

type HealthStatus struct {
	AgentUptime                string     `json:"agentUptime"`
	EnvoyPid                   string     `json:"envoyPid"`
	EnvoyState                 string     `json:"envoyState"`
	EnvoyRestartCount          string     `json:"envoyRestartCount"`
	ManagementServerConnection string     `json:"managementServerConnection"`
	ServerInfo                 ServerInfo `json:"serverInfo"`
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
	client         *retryablehttp.Client
	serverInfoReq  *retryablehttp.Request
	statsReq       *retryablehttp.Request
	agentStartTime time.Time
}

func (healthStatus *HealthStatus) pollEnvoyEndpoints(pollData *EnvoyEndpointHttpData, messageSources *messagesources.MessageSources) {

	healthStatus.AgentUptime = fmt.Sprintf("%.fs", time.Since(pollData.agentStartTime).Seconds())
	healthStatus.EnvoyPid = strconv.Itoa(messageSources.GetPid())
	healthStatus.EnvoyRestartCount = strconv.Itoa(messageSources.GetProcessRestartCount())

	response, err := pollData.client.Do(pollData.serverInfoReq)
	if err != nil {
		log.Error("Unable to reach Envoy Admin port: %w", err)
		healthStatus.EnvoyState = "UNREACHABLE"
	}

	if response != nil {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Warn("Unable to read server info response from Envoy: %w", err)
		}
		responseString := string(responseBody)
		healthStatus.EnvoyState = gjson.Get(responseString, "state").String()
		healthStatus.ServerInfo.Version = gjson.Get(responseString, "version").String()
		healthStatus.ServerInfo.ResourceArn = gjson.Get(responseString, "node.id").String()
		healthStatus.ServerInfo.CurrentUptime = gjson.Get(responseString, "uptime_current_epoch").String()
		healthStatus.ServerInfo.TotalUptime = gjson.Get(responseString, "uptime_all_epochs").String()

		response.Body.Close()
	}

	response, err = pollData.client.Do(pollData.statsReq)
	if err != nil {
		log.Error("Unable to reach Envoy Admin port: %w", err)
	}
	if response != nil {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Warn("Unable to read stats response from Envoy: %w", err)
		}
		responseString := string(responseBody)
		emsConnection := gjson.Get(responseString, `stats.#(name="control_plane.connected_state").value`).String()

		if emsConnection == "1" {
			healthStatus.ManagementServerConnection = "true"
		} else if emsConnection == "0" {
			healthStatus.ManagementServerConnection = "false"
		}
		response.Body.Close()
	}
}

func (healthStatus *HealthStatus) StartHealthCheck(
	agentStartTime time.Time,
	agentConfig config.AgentConfig,
	messageSources *messagesources.MessageSources) {

	var envoyEndPointData EnvoyEndpointHttpData

	// Initialize
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient.Timeout = 250 * time.Millisecond
	retryClient.RetryMax = 3
	retryClient.RetryWaitMin = 100 * time.Millisecond
	retryClient.RetryWaitMax = 1000 * time.Millisecond
	retryClient.Logger = nil // If this is not set retryablehttp client will write DEBUG logs on GET calls

	envoyEndPointData.client = retryClient

	var envoyAddress = "http://127.0.0.1"
	var queryString = "format=json"
	var serverInfoUrl = fmt.Sprintf("%s:%d%s",
		envoyAddress,
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyServerInfoUrl)
	var statsUrl = fmt.Sprintf("%s:%d%s?%s",
		envoyAddress,
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyServerStatsUrl,
		queryString)

	envoyEndPointData.serverInfoReq, _ = retryablehttp.NewRequest("GET", serverInfoUrl, nil)
	envoyEndPointData.serverInfoReq.Header.Add("Connection", "close")
	envoyEndPointData.serverInfoReq.Header.Add("User-Agent", config.APPNET_USER_AGENT)

	envoyEndPointData.statsReq, _ = retryablehttp.NewRequest("GET", statsUrl, nil)
	envoyEndPointData.statsReq.Header.Add("Connection", "close")
	envoyEndPointData.statsReq.Header.Add("User-Agent", config.APPNET_USER_AGENT)

	envoyEndPointData.agentStartTime = agentStartTime

	// Poll Envoy health once every 5 Envoy PID poll
	// Add Jitter between 10ms - 50ms
	jitter := time.Duration(rand.Intn(40)+10) * time.Millisecond
	ticker := time.NewTicker(agentConfig.HcPollInterval + jitter)
	defer ticker.Stop()

	// Loop forever
	for {
		select {
		case <-ticker.C:
			healthStatus.pollEnvoyEndpoints(&envoyEndPointData, messageSources)
		case <-messageSources.BlockingEnvoyStatusTrigger:
			healthStatus.pollEnvoyEndpoints(&envoyEndPointData, messageSources)
		}
	}
}
