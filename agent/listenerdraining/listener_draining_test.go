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

package listenerdraining

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/stretchr/testify/assert"
	rate "golang.org/x/time/rate"
)

func buildHandler(agentConfig *config.AgentConfig) EnvoyListenerDrainHandler {
	return EnvoyListenerDrainHandler{
		AgentConfig: *agentConfig,
		Limiter:     rate.NewLimiter(config.TPS_LIMIT, config.BURST_TPS_LIMIT),
	}
}

func TestEnvoyListenerDrainingGetRequest(t *testing.T) {

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	drainHandler := buildHandler(&agentConfig)

	srv := httptest.NewServer(http.HandlerFunc(drainHandler.HandleDraining))
	defer srv.Close()

	res, err := http.Get(srv.URL)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyListenerDrainingPostWithBody(t *testing.T) {
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	drainHandler := buildHandler(&agentConfig)
	srv := httptest.NewServer(http.HandlerFunc(drainHandler.HandleDraining))
	defer srv.Close()

	body := bytes.NewBuffer([]byte("PostRequestWithBody"))
	res, err := http.Post(srv.URL, "text/html", body)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyListenerDrainingPostWithNoParameters(t *testing.T) {

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	drainHandler := buildHandler(&agentConfig)

	srv := httptest.NewServer(http.HandlerFunc(drainHandler.HandleDraining))
	defer srv.Close()

	res, err := http.Post(srv.URL, "", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyListenerDrainingPostWithInvalidQueryParameters(t *testing.T) {

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	drainHandler := buildHandler(&agentConfig)

	srv := httptest.NewServer(http.HandlerFunc(drainHandler.HandleDraining))
	defer srv.Close()

	res, err := http.Post(fmt.Sprintf("%s?%s", srv.URL, "outboundonly"), "", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyListenerDrainingPostWithUnexpectedQueryParametersCount(t *testing.T) {

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	drainHandler := buildHandler(&agentConfig)

	srv := httptest.NewServer(http.HandlerFunc(drainHandler.HandleDraining))
	defer srv.Close()

	res, err := http.Post(fmt.Sprintf("%s?%s&%s", srv.URL, "outboundonly", "inboundonly"), "", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	defer res.Body.Close()

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvoyDrainInboundListeners(t *testing.T) {
	// Mock the Envoy server drain response
	sampleEnvoyDrainOutput := "inbound listener drained"
	envoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		queryParameters, _ := url.ParseQuery(request.URL.RawQuery)
		if queryParameters.Has(inboundOnlyQueryKey) {
			io.WriteString(writer, sampleEnvoyDrainOutput)
		}
	}))

	// Setup an http server that serves drain request
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentDrainHandler := buildHandler(&agentConfig)
	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	agentDrainHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	agentDrainHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	agentDrainHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())
	drainServer := httptest.NewServer(http.HandlerFunc(agentDrainHandler.HandleDraining))
	defer drainServer.Close()
	requestUrl := fmt.Sprintf("%s?%s", drainServer.URL, inboundOnlyQueryKey)
	res, err := http.Post(requestUrl, "text/html", nil)

	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	defer res.Body.Close()
	resBody, e := ioutil.ReadAll(res.Body)
	assert.NoError(t, e)
	assert.Equal(t, sampleEnvoyDrainOutput, string(resBody))
}
