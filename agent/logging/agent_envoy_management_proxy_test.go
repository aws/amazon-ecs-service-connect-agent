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

package logging

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/internal/netlistenertest"

	mux "github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	rate "golang.org/x/time/rate"
)

func buildHandler(agentConfig *config.AgentConfig) EnvoyLoggingHandler {
	return EnvoyLoggingHandler{
		AgentConfig: *agentConfig,
		Limiter:     rate.NewLimiter(config.TPS_LIMIT, config.BURST_TPS_LIMIT),
	}
}

func TestEnvoyLoggingLevelGetRequest(t *testing.T) {

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	envoyHandler := buildHandler(&agentConfig)

	srv := httptest.NewServer(http.HandlerFunc(envoyHandler.LoggingHandler))
	defer srv.Close()

	res, err := http.Get(srv.URL)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyLoggingLevelPostWithBody(t *testing.T) {
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	envoyHandler := buildHandler(&agentConfig)
	srv := httptest.NewServer(http.HandlerFunc(envoyHandler.LoggingHandler))
	defer srv.Close()

	body := bytes.NewBuffer([]byte("ICantSleepBecauseTheresaTigerInMyCloset"))
	res, err := http.Post(srv.URL, "text/html", body)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyLoggingLevelPostWithNoParameters(t *testing.T) {

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	envoyHandler := buildHandler(&agentConfig)

	srv := httptest.NewServer(http.HandlerFunc(envoyHandler.LoggingHandler))
	defer srv.Close()

	res, err := http.Post(srv.URL, "", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyLoggingLevelPostWithInvalidLevel(t *testing.T) {

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	envoyHandler := buildHandler(&agentConfig)
	srv := httptest.NewServer(http.HandlerFunc(envoyHandler.LoggingHandler))
	defer srv.Close()

	res, err := http.Post(fmt.Sprintf("%s?%s", srv.URL, "foolevel=debug"), "", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyLoggingLevelPostWithEncodedEquals(t *testing.T) {
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	envoyHandler := buildHandler(&agentConfig)
	srv := httptest.NewServer(http.HandlerFunc(envoyHandler.LoggingHandler))
	defer srv.Close()

	res, err := http.Post(fmt.Sprintf("%s/%s", srv.URL, "level%3ddebug"), "", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyLoggingLevelPostWithReservedCharacters(t *testing.T) {
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	envoyHandler := buildHandler(&agentConfig)
	srv := httptest.NewServer(http.HandlerFunc(envoyHandler.LoggingHandler))
	defer srv.Close()

	res, err := http.Post(fmt.Sprintf("%s/%s", srv.URL, "level=?^!@"), "", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func setupAndStartServerListener(t *testing.T, handler http.Handler, ctx *netlistenertest.ListenContext) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)

	err := server.Listener.Close()
	assert.Nil(t, err)
	server.Listener = *ctx.Listener

	server.Start()

	return server
}

func TestEnvoyLoggingLevelChange(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "tcp")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	var agentConfig config.AgentConfig

	var envoyCtx netlistenertest.ListenContext
	var agentCtx netlistenertest.ListenContext

	agentConfig.SetDefaults()
	err := agentCtx.GetPortListener()
	assert.Nil(t, err)
	agentConfig.AgentHttpPort = agentCtx.Port

	err = envoyCtx.CreateEnvoyAdminListener(&agentConfig)
	assert.Nil(t, err)

	defer envoyCtx.Close()
	defer agentCtx.Close()

	// =========================== Envoy Management Setup ===========================
	envoyRouter := mux.NewRouter()

	// Using a subset of the modules here for brevity
	logErrorResponse := `
active loggers:
	admin: error
	aws: error
	assert: error
	backtrace: error
	cache_filter: error
	client: error
	`
	envoyRouter.HandleFunc(agentConfig.EnvoyLoggingUrl,
		func(w http.ResponseWriter, r *http.Request) {
			// if there's a query parmeter where the level is debug return the debug reponse
			if r.URL.Query().Get("level") == "error" {
				io.WriteString(w, logErrorResponse)
				return
			}
			http.Error(w, "Invalid request for test", http.StatusBadRequest)
		})

	envoyManagmentServer := setupAndStartServerListener(
		t, envoyRouter, &envoyCtx)

	defer envoyManagmentServer.Close()

	// =========================== Agent Listener Setup ===========================

	agentRouter := mux.NewRouter()

	// Setup the Envoy logging handler
	envoyHandler := buildHandler(&agentConfig)
	agentRouter.HandleFunc(config.AGENT_LOGGING_ENDPOINT_URL, envoyHandler.LoggingHandler)

	agentHttpServer := setupAndStartServerListener(
		t, agentRouter, &agentCtx)
	defer agentHttpServer.Close()

	// Make a request to the agent to set the level.  If we get back a 200
	// It indicates we are successfully able to POST to Envoy and confirm we
	// updated the logging level
	url := fmt.Sprintf("%s%s?level=%s",
		agentHttpServer.URL, config.AGENT_LOGGING_ENDPOINT_URL, "error")

	log.Debugf("Using test url for agent [%s]\n", url)
	res, err := http.Post(url, "", nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestEnvoyLoggingLevelReset(t *testing.T) {
	os.Setenv("APPNET_AGENT_LOGGING_RESET_TIMEOUT", "2")
	defer os.Unsetenv("APPNET_AGENT_LOGGING_RESET_TIMEOUT")
	os.Setenv("ENVOY_ADMIN_MODE", "tcp")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	var envoyCtx netlistenertest.ListenContext
	var agentCtx netlistenertest.ListenContext

	err := agentCtx.GetPortListener()
	assert.Nil(t, err)
	agentConfig.AgentHttpPort = agentCtx.Port

	err = envoyCtx.CreateEnvoyAdminListener(&agentConfig)
	assert.Nil(t, err)

	defer envoyCtx.Close()
	defer agentCtx.Close()

	agentConfig.EnvoyLogLevel = "trace"

	// =========================== Envoy Management Setup ===========================
	envoyRouter := mux.NewRouter()

	// Using a subset of the modules here for brevity
	logTraceResponse := `
active loggers:
	admin: trace
	aws: trace
	assert: trace
	backtrace: trace
	cache_filter: trace
	client: trace
	`

	logDebugResponse := `
active loggers:
	admin: debug
	aws: debug
	assert: debug
	backtrace: debug
	cache_filter: debug
	client: debug
	`

	debugLevelSet := false
	var debugTimeStamp time.Time = time.Now()
	traceLevelSet := false
	var traceTimeStamp time.Time = time.Now()

	envoyRouter.HandleFunc(agentConfig.EnvoyLoggingUrl,
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("level") == "debug" {
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, logDebugResponse)
				debugLevelSet = true
				debugTimeStamp = time.Now()
				return
			}

			if r.URL.Query().Get("level") == "trace" {
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, logTraceResponse)
				traceLevelSet = true
				traceTimeStamp = time.Now()
				return
			}

			http.Error(w, "Invalid request for test", http.StatusBadRequest)
		})

	envoyManagmentServer := setupAndStartServerListener(
		t, envoyRouter, &envoyCtx)
	defer envoyManagmentServer.Close()

	// =========================== Agent Listener Setup ===========================

	agentRouter := mux.NewRouter()

	// Setup the Envoy logging handler
	envoyHandler := buildHandler(&agentConfig)
	agentRouter.HandleFunc(config.AGENT_LOGGING_ENDPOINT_URL, envoyHandler.LoggingHandler)

	agentHttpServer := setupAndStartServerListener(
		t, agentRouter, &agentCtx)
	defer agentHttpServer.Close()

	// Make a request to the agent to set the level.  We get back a 200
	// indicating we are successfully able to POST to Envoy and confirm
	// the logging level
	url := fmt.Sprintf("%s%s?level=%s",
		agentHttpServer.URL, config.AGENT_LOGGING_ENDPOINT_URL, "debug")

	log.Debugf("Using test url for agent [%s]\n", url)

	// Set the log level to debug
	res, err := http.Post(url, "", nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.True(t, debugLevelSet)

	// Try changing the log level again.  We should get back a 304
	res, err = http.Post(url, "", nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotModified, res.StatusCode)

	// Allow the goroutine to execute.  It's configured for 2 seconds
	time.Sleep(5 * time.Second)

	// Verify that our test server was called to reset the log level to trace
	delta := traceTimeStamp.Sub(debugTimeStamp)
	assert.True(t, traceLevelSet)
	assert.GreaterOrEqual(t, delta, int64(2))
}
