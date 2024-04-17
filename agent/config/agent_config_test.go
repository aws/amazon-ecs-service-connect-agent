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
	assert.Equal(t, AGENT_PORT_DEFAULT, agentConfig.AgentHttpPort)
	assert.Equal(t, AGENT_ADDRESS_DEFAULT, agentConfig.AgentHttpAddress)
	assert.Equal(t, ENVOY_ADMIN_PORT_DEFAULT, agentConfig.EnvoyServerAdminPort)
	assert.Equal(t, ENVOY_READY_ENDPOINT_URL, agentConfig.EnvoyReadyUrl)
	assert.Equal(t, ENVOY_STATS_ENDPOINT_URL, agentConfig.EnvoyServerStatsUrl)
	assert.Equal(t, ENVOY_LISTENER_DRAINING_ENDPOINT_URL, agentConfig.EnvoyListenerDrainUrl)
	assert.Equal(t, ENVOY_CONCURRENCY_DEFAULT, agentConfig.EnvoyConcurrency)
	assert.Equal(t, PID_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.PidPollInterval)
	assert.Equal(t, HC_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.HcPollInterval)
	assert.Equal(t, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT*time.Second, agentConfig.ListenerDrainWaitTime)
	assert.Equal(t, (LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT+PID_STOP_DELAY_SEC)*time.Second, agentConfig.StopProcessWaitTime)
	assert.Empty(t, agentConfig.EnvoyLoggingDestination)
	assert.Equal(t, "info", agentConfig.EnvoyLogLevel)
	assert.NotEmpty(t, agentConfig.EnvoyConfigPath)
	assert.True(t, strings.HasSuffix(agentConfig.EnvoyConfigPath, ".yaml"))
	assert.Empty(t, agentConfig.ClusterIPMapping)
	assert.False(t, agentConfig.EnvoyUseHttpClientToFetchAwsCredentials)
}

func TestPopulateAgentConfigWithEnvVars(t *testing.T) {
	os.Setenv("APPNET_AGENT_HTTP_PORT", "8888")
	os.Setenv("APPNET_AGENT_HTTP_BIND_ADDRESS", "127.0.0.2")
	defer os.Unsetenv("APPNET_AGENT_HTTP_PORT")
	defer os.Unsetenv("APPNET_AGENT_HTTP_BIND_ADDRESS")

	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, 8888, agentConfig.AgentHttpPort)
	assert.Equal(t, "127.0.0.2", agentConfig.AgentHttpAddress)
}

func TestOffLogLevel(t *testing.T) {
	os.Setenv("ENVOY_LOG_LEVEL", "off")
	defer os.Unsetenv("ENVOY_LOG_LEVEL")
	var agentConfig AgentConfig

	args := []string{os.Args[0], "-envoyConfigPath", "/tmp/config.yaml"}

	agentConfig.ParseFlags(args)
	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.NotNil(t, agentConfig.EnvoyLogLevel)
	assert.Equal(t, "off", agentConfig.EnvoyLogLevel)
}

func TestInvalidLogLevel(t *testing.T) {
	os.Setenv("ENVOY_LOG_LEVEL", "doomsday")
	defer os.Unsetenv("ENVOY_LOG_LEVEL")
	var agentConfig AgentConfig

	args := []string{os.Args[0], "-envoyConfigPath", "/tmp/config.yaml"}

	agentConfig.ParseFlags(args)
	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.NotNil(t, agentConfig.EnvoyLogLevel)
	assert.Equal(t, "info", agentConfig.EnvoyLogLevel)
}

func TestInvalidEnvoyAdminMode(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "invalid")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, TCP, agentConfig.EnvoyAdminMode)
}

func TestEnvoyAdminModeUds(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "uds")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, UDS, agentConfig.EnvoyAdminMode)
}

func TestEnvoyOverrideUseHttpClient(t *testing.T) {
	os.Setenv("ENVOY_USE_HTTP_CLIENT_TO_FETCH_AWS_CREDENTIALS", "true")
	defer os.Unsetenv("ENVOY_USE_HTTP_CLIENT_TO_FETCH_AWS_CREDENTIALS")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.True(t, agentConfig.EnvoyUseHttpClientToFetchAwsCredentials)
}

func TestEnableRelayModeForXds(t *testing.T) {
	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "1")
	os.Setenv("APPNET_AGENT_ADMIN_MODE", "UDS")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")
	defer os.Unsetenv("APPNET_AGENT_ADMIN_MODE")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, true, agentConfig.EnableRelayModeForXds)
	assert.Equal(t, "/var/run/ecs/appnet_admin.sock", agentConfig.AgentAdminUdsPath)
	assert.Equal(t, "/tmp/relay_xds.sock", agentConfig.AppNetRelayListenerUdsPath)
	assert.Equal(t, SocketType(1), agentConfig.AgentAdminMode)
	assert.Equal(t, 443, agentConfig.AppNetManagementPort)
	assert.Equal(t, "2400s", agentConfig.RelayStreamIdleTimeout)
	assert.Equal(t, 10485760, agentConfig.RelayBufferLimitBytes)
	assert.False(t, agentConfig.EnvoyUseHttpClientToFetchAwsCredentials)
}

func TestEnableRelayModeForXds_domainWithScheme(t *testing.T) {
	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "1")
	os.Setenv("APPNET_AGENT_ADMIN_MODE", "UDS")
	os.Setenv("APPMESH_XDS_ENDPOINT", "https://ecs-sc.us-west-2.aws.api")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")
	defer os.Unsetenv("APPNET_AGENT_ADMIN_MODE")
	defer os.Unsetenv("APPMESH_XDS_ENDPOINT")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, true, agentConfig.EnableRelayModeForXds)
	assert.Equal(t, "/var/run/ecs/appnet_admin.sock", agentConfig.AgentAdminUdsPath)
	assert.Equal(t, "/tmp/relay_xds.sock", agentConfig.AppNetRelayListenerUdsPath)
	assert.Equal(t, 443, agentConfig.AppNetManagementPort)
	assert.Equal(t, "ecs-sc.us-west-2.aws.api", agentConfig.AppNetManagementDomainName)
	assert.Equal(t, "2400s", agentConfig.RelayStreamIdleTimeout)
	assert.Equal(t, 10485760, agentConfig.RelayBufferLimitBytes)
}

func TestEnableRelayModeForXds_OverrideIdleTimeoutAndBufferLimit(t *testing.T) {
	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "1")
	os.Setenv("APPNET_AGENT_ADMIN_MODE", "UDS")
	os.Setenv("RELAY_STREAM_IDLE_TIMEOUT", "300s")
	os.Setenv("RELAY_BUFFER_LIMIT_BYTES", "32768")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")
	defer os.Unsetenv("APPNET_AGENT_ADMIN_MODE")
	defer os.Unsetenv("RELAY_STREAM_IDLE_TIMEOUT")
	defer os.Unsetenv("RELAY_BUFFER_LIMIT_BYTES")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, true, agentConfig.EnableRelayModeForXds)
	assert.Equal(t, "/var/run/ecs/appnet_admin.sock", agentConfig.AgentAdminUdsPath)
	assert.Equal(t, "/tmp/relay_xds.sock", agentConfig.AppNetRelayListenerUdsPath)
	assert.Equal(t, SocketType(1), agentConfig.AgentAdminMode)
	assert.Equal(t, 443, agentConfig.AppNetManagementPort)
	assert.Equal(t, "300s", agentConfig.RelayStreamIdleTimeout)
	assert.Equal(t, 32768, agentConfig.RelayBufferLimitBytes)
}

func TestUdsEndpoint(t *testing.T) {
	os.Setenv("APPMESH_XDS_ENDPOINT", "unix:///tmp/xds-envoy-test.sock")
	defer os.Unsetenv("APPMESH_XDS_ENDPOINT")
	var agentConfig AgentConfig

	agentConfig.SetDefaults()

	assert.Equal(t, "unix:///tmp/xds-envoy-test.sock", agentConfig.XdsEndpointUdsPath)
}

func TestCustomEnvoyConfigFileIsValid(t *testing.T) {
	// Create a dummy envoy custom config file on disk and
	// set it's path to env `ENVOY_CONFIG_FILE`
	const customEnvoyConfigPath string = "/tmp/envoy_config.yaml"
	os.Setenv("ENVOY_CONFIG_FILE", customEnvoyConfigPath)

	err := os.WriteFile(customEnvoyConfigPath, []byte("---"), 0600)
	assert.Nil(t, err)

	defer os.Remove(customEnvoyConfigPath)
	defer os.Unsetenv("ENVOY_CONFIG_FILE")

	var agentConfig AgentConfig
	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.NotNil(t, agentConfig.EnvoyConfigPath)
	assert.Equal(t, customEnvoyConfigPath, agentConfig.EnvoyConfigPath)
}

func TestPopulateAgentConfigWithFlagsSet(t *testing.T) {

	const logLevel string = "debug"
	const configPath string = "/tmp/config.yaml"

	// Create a dummy config file on disk since we are checking
	// that the config file exists and has content
	err := os.WriteFile(configPath, []byte("dummydata"), 0600)
	assert.Nil(t, err)

	defer os.Remove(configPath)

	args := []string{os.Args[0], "-logLevel", logLevel, "-envoyConfigPath", configPath}

	var agentConfig AgentConfig

	agentConfig.ParseFlags(args)
	agentConfig.SetDefaults()

	assert.NotNil(t, agentConfig)
	assert.Equal(t, logLevel, agentConfig.EnvoyLogLevel)
	assert.Equal(t, configPath, agentConfig.EnvoyConfigPath)
}

func TestTimerValidations(t *testing.T) {
	var agentConfig AgentConfig

	// Unset env variables when func exits
	defer os.Unsetenv("APPNET_ENVOY_RESTART_COUNT")
	defer os.Unsetenv("PID_POLL_INTERVAL_MS")
	defer os.Unsetenv("HC_POLL_INTERVAL_MS")
	defer os.Unsetenv("LISTENER_DRAIN_WAIT_TIME_S")
	defer os.Unsetenv("HC_DISCONNECTED_TIMEOUT_S")

	// Test minimum bounds
	os.Setenv("APPNET_ENVOY_RESTART_COUNT", "-1")
	os.Setenv("PID_POLL_INTERVAL_MS", "50")
	os.Setenv("HC_POLL_INTERVAL_MS", "1999")
	os.Setenv("LISTENER_DRAIN_WAIT_TIME_S", "4")
	os.Setenv("HC_DISCONNECTED_TIMEOUT_S", "100")
	agentConfig.SetDefaults()

	assert.Equal(t, ENVOY_RESTART_COUNT_DEFAULT, agentConfig.EnvoyRestartCount)
	assert.Equal(t, PID_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.PidPollInterval)
	assert.Equal(t, HC_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.HcPollInterval)
	assert.Equal(t, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT*time.Second, agentConfig.ListenerDrainWaitTime)
	assert.Equal(t, HC_DISCONNECTED_TIMEOUT_S_DEFAULT*time.Second, agentConfig.HcDisconnectedTimeout)

	// Test maximum bounds
	os.Setenv("APPNET_ENVOY_RESTART_COUNT", "11")
	os.Setenv("PID_POLL_INTERVAL_MS", "1001")
	os.Setenv("HC_POLL_INTERVAL_MS", "30001")
	os.Setenv("LISTENER_DRAIN_WAIT_TIME_S", "111")
	os.Setenv("HC_DISCONNECTED_TIMEOUT_S", "700000")
	agentConfig.SetDefaults()

	assert.Equal(t, ENVOY_RESTART_COUNT_MAX, agentConfig.EnvoyRestartCount)
	assert.Equal(t, PID_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.PidPollInterval)
	assert.Equal(t, HC_POLL_INTERVAL_MS_DEFAULT*time.Millisecond, agentConfig.HcPollInterval)
	assert.Equal(t, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT*time.Second, agentConfig.ListenerDrainWaitTime)
	assert.Equal(t, HC_DISCONNECTED_TIMEOUT_S_DEFAULT*time.Second, agentConfig.HcDisconnectedTimeout)
}

func TestGetHcPollInterval(t *testing.T) {
	var agentConfig AgentConfig
	defer os.Unsetenv("HC_POLL_INTERVAL_MS")
	defer os.Unsetenv("APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S")
	// Test HC_POLL_INTERVAL_MS_DEFAULT used
	agentConfig.SetDefaults()
	assert.Equal(t, 10000*time.Millisecond, agentConfig.HcPollInterval)

	// Test APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S honored
	os.Setenv("APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S", "6")
	agentConfig.SetDefaults()
	assert.Equal(t, 6000*time.Millisecond, agentConfig.HcPollInterval)

	// Test HC_POLL_INTERVAL_MS honored
	os.Setenv("HC_POLL_INTERVAL_MS", "2001")
	os.Setenv("APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S", "5")
	agentConfig.SetDefaults()
	assert.Equal(t, 2001*time.Millisecond, agentConfig.HcPollInterval)
}
