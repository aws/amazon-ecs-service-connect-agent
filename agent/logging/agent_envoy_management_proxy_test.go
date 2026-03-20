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

func TestEnvoyLoggingLevelPostWithUnknownExtraParameter(t *testing.T) {
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	envoyHandler := buildHandler(&agentConfig)
	srv := httptest.NewServer(http.HandlerFunc(envoyHandler.LoggingHandler))
	defer srv.Close()

	res, err := http.Post(fmt.Sprintf("%s?level=debug&unknown=true", srv.URL), "", nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	defer res.Body.Close()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyLoggingLevelResetBehavior(t *testing.T) {
	tests := []struct {
		name                  string
		permanentParam        string
		expectReset           bool
		expectedReRequestCode int
	}{
		{"resets after timeout without permanent flag", "", true, http.StatusOK},
		{"no reset with permanent=true", "&permanent=true", false, http.StatusNotModified},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("APPNET_AGENT_LOGGING_RESET_TIMEOUT", "2")
			defer os.Unsetenv("APPNET_AGENT_LOGGING_RESET_TIMEOUT")
			os.Setenv("ENVOY_ADMIN_MODE", "tcp")
			defer os.Unsetenv("ENVOY_ADMIN_MODE")

			var agentConfig config.AgentConfig
			agentConfig.SetDefaults()
			agentConfig.EnvoyLogLevel = "trace"

			var debugTimestamp, resetTimestamp time.Time
			resetCalled := false

			agentURL, cleanup := setupLoggingTestServers(t, &agentConfig,
				func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Query().Get("level") {
					case "debug":
						debugTimestamp = time.Now()
						io.WriteString(w, "active loggers:\n\tadmin: debug\n")
					case "trace":
						resetTimestamp = time.Now()
						resetCalled = true
						io.WriteString(w, "active loggers:\n\tadmin: trace\n")
					default:
						http.Error(w, "unexpected level", http.StatusBadRequest)
					}
				})
			defer cleanup()

			url := fmt.Sprintf("%s%s?level=debug%s", agentURL, config.AGENT_LOGGING_ENDPOINT_URL, tc.permanentParam)

			res, err := http.Post(url, "", nil)
			assert.Nil(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode)

			// A second request while a reset is pending should be a no-op
			if tc.permanentParam == "" {
				res, err = http.Post(url, "", nil)
				assert.Nil(t, err)
				assert.Equal(t, http.StatusNotModified, res.StatusCode)
			}

			time.Sleep(5 * time.Second)

			assert.Equal(t, tc.expectReset, resetCalled)
			if tc.expectReset {
				assert.GreaterOrEqual(t, resetTimestamp.Sub(debugTimestamp), 2*time.Second)
			}
			res, err = http.Post(url, "", nil)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedReRequestCode, res.StatusCode)
		})
	}
}

func setupAndStartServerListener(t *testing.T, handler http.Handler, ctx *netlistenertest.ListenContext) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)

	err := server.Listener.Close()
	assert.Nil(t, err)
	server.Listener = *ctx.Listener

	server.Start()

	return server
}

func setupLoggingTestServers(t *testing.T, agentConfig *config.AgentConfig, envoyHandler func(http.ResponseWriter, *http.Request)) (agentBaseURL string, cleanup func()) {
	var envoyCtx, agentCtx netlistenertest.ListenContext

	err := agentCtx.GetPortListener()
	assert.Nil(t, err)
	agentConfig.AgentHttpPort = agentCtx.Port

	err = envoyCtx.CreateEnvoyAdminListener(agentConfig)
	assert.Nil(t, err)

	envoyRouter := mux.NewRouter()
	envoyRouter.HandleFunc(agentConfig.EnvoyLoggingUrl, envoyHandler)
	envoyServer := setupAndStartServerListener(t, envoyRouter, &envoyCtx)

	agentRouter := mux.NewRouter()
	handler := buildHandler(agentConfig)
	agentRouter.HandleFunc(config.AGENT_LOGGING_ENDPOINT_URL, handler.LoggingHandler)
	agentServer := setupAndStartServerListener(t, agentRouter, &agentCtx)

	return agentServer.URL, func() {
		envoyServer.Close()
		agentServer.Close()
		envoyCtx.Close()
		agentCtx.Close()
	}
}
