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

package client

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/internal/netlistenertest"

	"github.com/stretchr/testify/assert"
)

func validateDefaultHttpClientForEnvoyServer(t *testing.T) {
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	envoy := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		io.WriteString(writer, "Success")
	}))
	defer envoy.Close()
	// Create a new listener to listen on Envoy Admin Port
	var envoyListenCtx netlistenertest.ListenContext
	err := envoyListenCtx.CreateEnvoyAdminListener(&agentConfig)
	assert.Nil(t, err)
	defer envoyListenCtx.Close()

	// Close the httptest listener as it listens on port 80 by default
	err = envoy.Listener.Close()
	assert.Nil(t, err)

	// Attach the new listener to the httptest server
	envoy.Listener = *envoyListenCtx.Listener
	envoy.Start()

	httpClient, err := CreateDefaultHttpClientForEnvoyServer(agentConfig)
	assert.Nil(t, err)

	testUrl := fmt.Sprintf("%s://%s:%d/test",
		agentConfig.EnvoyServerScheme,
		agentConfig.EnvoyServerHostName,
		agentConfig.EnvoyServerAdminPort)
	request, err := CreateStandardAgentHttpRequest("GET", testUrl, nil)
	assert.Nil(t, err)
	response, err := httpClient.Do(request)
	assert.Nil(t, err)

	responseBody, err := io.ReadAll(response.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "Success", string(responseBody))

	response.Body.Close()
}

func TestCreateDefaultHttpClientForEnvoyServer_TCP(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "tcp")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	validateDefaultHttpClientForEnvoyServer(t)
}

func TestCreateDefaultHttpClientForEnvoyServer_UDS(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "uds")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	validateDefaultHttpClientForEnvoyServer(t)
}

func TestCreateRetryableHttpClientForAgentServer(t *testing.T) {
	t.Run("return error when no socket exists", func(t *testing.T) {
		conf := config.AgentConfig{}
		c, err := CreateHttpClientForAgentServer(conf)

		assert.Error(t, err)
		assert.Nil(t, c)
	})

	t.Run("return client", func(t *testing.T) {
		conf := config.AgentConfig{}
		tmpFile, err := ioutil.TempFile(os.TempDir(), "agent.sock")
		if err != nil {
			t.Errorf("failed to create temp file: %v", err)
		}

		conf.AgentAdminUdsPath = tmpFile.Name()
		c, err := CreateHttpClientForAgentServer(conf)

		assert.Nil(t, err)
		assert.NotNil(t, c)

		// cleanup
		os.Remove(tmpFile.Name())
	})
}
