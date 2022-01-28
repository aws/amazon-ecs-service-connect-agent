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

package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPopulateDefaultAgentConfig(t *testing.T) {
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, ENVOY_ADMIN_PORT_DEFAULT, agentConfig.EnvoyServerAdminPort)
	assert.Equal(t, ENVOY_SERVER_INFO_ENDPOINT_URL, agentConfig.EnvoyServerInfoUrl)
	assert.Equal(t, ENVOY_STATS_ENDPOINT_URL, agentConfig.EnvoyServerStatsUrl)
	assert.Equal(t, ENVOY_LISTENER_DRAINING_ENDPOINT_URL, agentConfig.EnvoyListenerDrainUrl)
	assert.Equal(t, PID_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.PidPollInterval)
	assert.Equal(t, HC_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.HcPollInterval)
	assert.Equal(t, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT*time.Second, agentConfig.ListenerDrainWaitTime)
	assert.Equal(t, (LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT+PID_STOP_DELAY_SEC)*time.Second, agentConfig.StopProcessWaitTime)
	assert.Empty(t, agentConfig.EnvoyLoggingDestination)
	assert.Equal(t, "info", *agentConfig.EnvoyLogLevel)
	assert.NotNil(t, agentConfig.EnvoyConfigPath)
	assert.NotEmpty(t, *agentConfig.EnvoyConfigPath)
	assert.True(t, strings.HasSuffix(*agentConfig.EnvoyConfigPath, ".yaml"))
	assert.Empty(t, agentConfig.ApplicationPortMapping)
}

func TestInvalidLogLevel(t *testing.T) {
	os.Setenv("ENVOY_LOG_LEVEL", "doomsday")
	defer os.Unsetenv("ENVOY_LOG_LEVEL")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.NotNil(t, agentConfig.EnvoyLogLevel)
	assert.Equal(t, "info", *agentConfig.EnvoyLogLevel)
}

func TestPopulateAgentConfigWithFlagsSet(t *testing.T) {

	const logLevel string = "debug"
	const configPath string = "/tmp/config.yaml"

	// Create a dummy config file on disk since we are checking
	// that the config file exists and has content
	err := os.WriteFile(configPath, []byte("dummydata"), 0600)
	assert.Nil(t, err)

	defer os.Remove(configPath)

	oldArgs := os.Args
	os.Args = []string{oldArgs[0], "-logLevel", logLevel, "-envoyConfigPath", configPath}

	var agentConfig AgentConfig

	agentConfig.SetDefaults()
	os.Args = oldArgs

	assert.NotNil(t, agentConfig)
	assert.Equal(t, logLevel, *agentConfig.EnvoyLogLevel)
	assert.Equal(t, configPath, *agentConfig.EnvoyConfigPath)
}

func TestTimerValidations(t *testing.T) {
	var agentConfig AgentConfig

	// Unset env variables when func exits
	defer os.Unsetenv("APPNET_ENVOY_RESTART_COUNT")
	defer os.Unsetenv("PID_POLL_INTERVAL_MS")
	defer os.Unsetenv("HC_POLL_INTERVAL_MS")
	defer os.Unsetenv("LISTENER_DRAIN_WAIT_TIME_S")

	// Test minimum bounds
	os.Setenv("APPNET_ENVOY_RESTART_COUNT", "-1")
	os.Setenv("PID_POLL_INTERVAL_MS", "50")
	os.Setenv("HC_POLL_INTERVAL_MS", "1999")
	os.Setenv("LISTENER_DRAIN_WAIT_TIME_S", "4")
	agentConfig.SetDefaults()

	assert.Equal(t, ENVOY_RESTART_COUNT_DEFAULT, agentConfig.EnvoyRestartCount)
	assert.Equal(t, PID_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.PidPollInterval)
	assert.Equal(t, HC_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.HcPollInterval)
	assert.Equal(t, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT*time.Second, agentConfig.ListenerDrainWaitTime)

	// Test maximum bounds
	os.Setenv("APPNET_ENVOY_RESTART_COUNT", "11")
	os.Setenv("PID_POLL_INTERVAL_MS", "1001")
	os.Setenv("HC_POLL_INTERVAL_MS", "3001")
	os.Setenv("LISTENER_DRAIN_WAIT_TIME_S", "111")
	agentConfig.SetDefaults()

	assert.Equal(t, ENVOY_RESTART_COUNT_MAX, agentConfig.EnvoyRestartCount)
	assert.Equal(t, PID_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.PidPollInterval)
	assert.Equal(t, HC_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.HcPollInterval)
	assert.Equal(t, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT*time.Second, agentConfig.ListenerDrainWaitTime)
}
