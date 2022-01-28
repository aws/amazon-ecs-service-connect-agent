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
	"flag"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	bootstrap "github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap"

	log "github.com/sirupsen/logrus"
)

const (
	ENVOY_RESTART_COUNT_DEFAULT          = 0
	ENVOY_RESTART_COUNT_MAX              = 10
	ENVOY_ADMIN_PORT_DEFAULT             = 9901
	ENVOY_SERVER_INFO_ENDPOINT_URL       = "/server_info"
	ENVOY_STATS_ENDPOINT_URL             = "/stats"
	ENVOY_LOGGING_ENDPOINT_URL           = "/logging"
	ENVOY_LISTENER_DRAINING_ENDPOINT_URL = "/drain_listeners?graceful"

	// agent handled endpoints
	AGENT_STATUS_ENDPOINT_URL  = "/status"
	AGENT_LOGGING_ENDPOINT_URL = "/enableLogging"
	APPNET_USER_AGENT          = "appnetClient/1.0"
	AGENT_LOG_IDENTIFIER       = "AppNet Agent"

	// Note that if the environment variable controlling the
	// logging destination (APPNET_ENVOY_LOG_DESTINATION) is
	// not set, or is set to an empty string, we will not alter
	// the output destination. It remains as stdout/stderr
	ENVOY_LOG_DESTINATION_DEFAULT   = ""
	ENVOY_LOG_FILE_NAME_DEFAULT     = "appnet_envoy.log"
	AGENT_MAX_LOG_FILE_SIZE_DEFAULT = 1.0
	AGENT_MAX_LOG_RETENTION_DEFAULT = 5

	// PID polling timers
	PID_POLL_INTERVAL_MS_DEFAULT = 100
	PID_POLL_INTERVAL_MS_MIN     = 100
	PID_POLL_INTERVAL_MS_MAX     = 1000

	// HealthCheck polling timers
	HC_POLL_INTERVAL_MS_DEFAULT = 2000
	HC_POLL_INTERVAL_MS_MIN     = 2000
	HC_POLL_INTERVAL_MS_MAX     = 3000

	// ECS stopTimeout is 30sec by default and can be set to maximum 120sec
	LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT = 20
	LISTENER_DRAIN_WAIT_TIME_SEC_MIN     = 5
	LISTENER_DRAIN_WAIT_TIME_SEC_MAX     = 110
	// Wait 3 seconds for Envoy to exit, before we kill it
	PID_STOP_DELAY_SEC = 3

	AGENT_ADDRESS_DEFAULT = "0.0.0.0"

	AGENT_LOGGING_RESET_TIMEOUT_S_DEFAULT = 300

	// Rate limiter constants
	TPS_LIMIT       = 10
	BURST_TPS_LIMIT = 20
)

type AgentConfig struct {
	CommandPath             string
	CommandArgs             []string
	AgentHttpPort           int
	AgentHttpAddress        string
	AgentLoglevelReset      time.Duration
	EnvoyRestartCount       int
	EnvoyServerAdminPort    int
	EnvoyServerInfoUrl      string
	EnvoyServerStatsUrl     string
	EnvoyListenerDrainUrl   string
	EnvoyLoggingUrl         string
	EnvoyLoggingDestination string
	EnvoyLogFileName        string
	EnvoyLogLevel           *string
	EnvoyConfigPath         *string
	ApplicationPortMapping  string
	MaxLogFileSizeMB        float64
	MaxLogCount             int

	// Poll intervals
	PidPollInterval       time.Duration
	HcPollInterval        time.Duration
	ListenerDrainWaitTime time.Duration
	StopProcessWaitTime   time.Duration

	// fields that are not controllable by the user
	OutputFileDescriptors []uintptr
}

func getEnvValueAsFloat(varName string, defaultValue float64) float64 {

	value, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue
	}

	envValue, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.Debugf("Unable to get a usable float value from environment variable [%s]\n", varName)
		return defaultValue
	}

	return envValue
}

func getEnvValueAsInt(varName string, defaultValue int) int {

	value, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue
	}

	envValue, err := strconv.Atoi(value)
	if err != nil {
		log.Debugf("Unable to get a usable integer value from environment variable [%s]\n", varName)
		return defaultValue
	}

	return envValue
}

func getEnvValueAsString(varName string, defaultValue string) string {

	value, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue
	}

	if len(value) == 0 {
		log.Debugf("Unable to get a usable string value from environment variable [%s]\n", varName)
		return defaultValue
	}

	return value
}

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}

func getDefaultBootstrapFilePath() string {

	tmpFile, err := ioutil.TempFile(os.TempDir(), "envoy-config-*.yaml")
	if err != nil {
		log.Errorf("Cannot create bootstrap file. %v", err)
	}

	envoyConfigYaml, err := bootstrap.GetBootstrapYaml()

	if err != nil {
		log.Error("Exiting the Agent since Envoy is not able to start with a valid configuration.")
		os.Exit(1)
	}

	_, err = tmpFile.Write([]byte(envoyConfigYaml))
	if err != nil {
		log.Errorf("Cannot write bootstrap config to file. %v", err)
		log.Error("Exiting the Agent since Envoy is not able to start with a valid configuration file.")
		os.Exit(1)
	}

	return tmpFile.Name()
}

func validateTimers(config *AgentConfig) {
	if config.EnvoyRestartCount < 0 {
		config.EnvoyRestartCount = ENVOY_RESTART_COUNT_DEFAULT
	}

	if config.EnvoyRestartCount > ENVOY_RESTART_COUNT_MAX {
		log.Warnf("APPNET_ENVOY_RESTART_COUNT cannot be greater than %d, setting it to maximum value %d",
			ENVOY_RESTART_COUNT_MAX, ENVOY_RESTART_COUNT_MAX)
		config.EnvoyRestartCount = ENVOY_RESTART_COUNT_MAX
	}

	if config.PidPollInterval < PID_POLL_INTERVAL_MS_MIN*time.Millisecond {
		log.Warnf("PID_POLL_INTERVAL_MS cannot be less than %dms, setting it to %dms as a default",
			PID_POLL_INTERVAL_MS_MIN, PID_POLL_INTERVAL_MS_DEFAULT)
		config.PidPollInterval = PID_POLL_INTERVAL_MS_DEFAULT * time.Millisecond
	}

	if config.PidPollInterval > PID_POLL_INTERVAL_MS_MAX*time.Millisecond {
		log.Warnf("PID_POLL_INTERVAL_MS cannot be greater than %dms, setting it to %dms as a default",
			PID_POLL_INTERVAL_MS_MAX, PID_POLL_INTERVAL_MS_DEFAULT)
		config.PidPollInterval = PID_POLL_INTERVAL_MS_DEFAULT * time.Millisecond
	}

	if config.HcPollInterval < HC_POLL_INTERVAL_MS_MIN*time.Millisecond {
		log.Warnf("HC_POLL_INTERVAL_MS cannot be less than %dms, setting it to %dms as a default",
			HC_POLL_INTERVAL_MS_MIN, HC_POLL_INTERVAL_MS_DEFAULT)
		config.HcPollInterval = HC_POLL_INTERVAL_MS_DEFAULT * time.Millisecond
	}

	if config.HcPollInterval > HC_POLL_INTERVAL_MS_MAX*time.Millisecond {
		log.Warnf("HC_POLL_INTERVAL_MS cannot be greater than %dms, setting it to %dms as a default",
			HC_POLL_INTERVAL_MS_MAX, HC_POLL_INTERVAL_MS_DEFAULT)
		config.HcPollInterval = HC_POLL_INTERVAL_MS_DEFAULT * time.Millisecond
	}

	if config.ListenerDrainWaitTime < LISTENER_DRAIN_WAIT_TIME_SEC_MIN*time.Second {
		log.Warnf("LISTENER_DRAIN_WAIT_TIME_S cannot be lesser than %ds, setting it to %ds as a default",
			LISTENER_DRAIN_WAIT_TIME_SEC_MIN, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT)
		config.ListenerDrainWaitTime = LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT * time.Second
	}

	if config.ListenerDrainWaitTime > LISTENER_DRAIN_WAIT_TIME_SEC_MAX*time.Second {
		log.Warnf("LISTENER_DRAIN_WAIT_TIME_S cannot be greater than %ds, setting it to %ds as a default",
			LISTENER_DRAIN_WAIT_TIME_SEC_MAX, LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT)
		config.ListenerDrainWaitTime = LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT * time.Second
	}

	config.StopProcessWaitTime = config.ListenerDrainWaitTime + PID_STOP_DELAY_SEC*time.Second
}

func validateEnvoyConfigPath(configPath **string) {

	path := *configPath

	// Verify that configPath is a file on disk
	statInfo, err := os.Lstat(*path)
	if err != nil {
		log.Warnf("Unable to verify %s is a valid disk file", *path)
		*path = ""
	}

	if statInfo != nil {
		mode := statInfo.Mode()
		if !mode.IsRegular() || statInfo.Size() == 0 {
			log.Warnf("Unable to establish %s is a regular disk file", *path)
			*path = ""
		}
	}
}

// validate that the log level is a known value otherwise use the default
func validateEnvoyLogLevel(logLevel **string) {
	level := *logLevel

	switch *level {
	case "info":
		fallthrough
	case "debug":
		fallthrough
	case "warn":
		fallthrough
	case "error":
		fallthrough
	case "trace":
		return
	default:
		*level = "info"
	}

}

func (config *AgentConfig) SetDefaults() {

	// Define command line flags that must be supplied
	resetFlags()

	envoyConfigPath := flag.String("envoyConfigPath", "", "envoy bootstrap config path")

	// Unless specified as a parameter to the agent use ENVOY_LOG_LEVEL
	defaultLogLevel := strings.ToLower(getEnvValueAsString("ENVOY_LOG_LEVEL", "info"))
	envoyLogLevel := flag.String("logLevel", defaultLogLevel, "the log level (e.g. debug, info)")
	flag.Parse()

	config.CommandPath = "/usr/bin/envoy"

	config.EnvoyRestartCount = getEnvValueAsInt("APPNET_ENVOY_RESTART_COUNT", ENVOY_RESTART_COUNT_DEFAULT)
	config.EnvoyServerAdminPort = getEnvValueAsInt("APPNET_ENVOY_MANAGEMENT_PORT", ENVOY_ADMIN_PORT_DEFAULT)
	config.EnvoyServerInfoUrl = ENVOY_SERVER_INFO_ENDPOINT_URL
	config.EnvoyServerStatsUrl = ENVOY_STATS_ENDPOINT_URL
	config.EnvoyLoggingUrl = ENVOY_LOGGING_ENDPOINT_URL
	config.EnvoyListenerDrainUrl = ENVOY_LISTENER_DRAINING_ENDPOINT_URL

	// Logging
	config.EnvoyLoggingDestination = getEnvValueAsString("APPNET_ENVOY_LOG_DESTINATION", ENVOY_LOG_DESTINATION_DEFAULT)
	config.EnvoyLogFileName = getEnvValueAsString("APPNET_ENVOY_LOG_NAME", ENVOY_LOG_FILE_NAME_DEFAULT)

	config.MaxLogFileSizeMB = getEnvValueAsFloat("AGENT_MAX_LOG_FILE_SIZE", AGENT_MAX_LOG_FILE_SIZE_DEFAULT)
	config.MaxLogCount = getEnvValueAsInt("APPNET_AGENT_MAX_RETENTION_COUNT", AGENT_MAX_LOG_RETENTION_DEFAULT)

	if *envoyConfigPath == "" {
		*envoyConfigPath = getDefaultBootstrapFilePath()
	}

	// If the file path cannot be verified, we will set the path to nil.  This prevents the parameter from being used
	// and will cause the task to fail. Unless the bootstrap generation fails, this function should be a no-op
	validateEnvoyConfigPath(&envoyConfigPath)

	config.EnvoyConfigPath = envoyConfigPath
	config.EnvoyLogLevel = envoyLogLevel

	validateEnvoyLogLevel(&envoyLogLevel)

	config.ApplicationPortMapping = "" // For service connect, we expect this to be populated with a json string

	// Timers
	config.PidPollInterval = time.Duration(
		getEnvValueAsInt("PID_POLL_INTERVAL_MS", PID_POLL_INTERVAL_MS_DEFAULT)) * time.Millisecond
	config.HcPollInterval = time.Duration(
		getEnvValueAsInt("HC_POLL_INTERVAL_MS", HC_POLL_INTERVAL_MS_DEFAULT)) * time.Millisecond
	config.ListenerDrainWaitTime = time.Duration(
		getEnvValueAsInt("LISTENER_DRAIN_WAIT_TIME_S", LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT)) * time.Second
	validateTimers(config)
}
