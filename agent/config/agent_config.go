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
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type SocketType int

const (
	TCP SocketType = iota
	UDS
)

const (
	NETWORK_SOCKET_UNIX = "unix"
	NETWORK_SOCKET_TCP  = "tcp"
	URI_UNIX_PREFIX     = "unix://"
	URL_HTTP_SCHEME     = "http://"
	URL_HTTPS_SCHEME    = "https://"
)

const (
	AGENT_PORT_DEFAULT                            = 9902
	AGENT_ADMIN_MODE_DEFAULT                      = "tcp"
	AGENT_ADMIN_UDS_PATH_DEFAULT                  = "/var/run/ecs/appnet_admin.sock"
	AGENT_POLL_ENVOY_READINESS_INTERVAL_S_DEFAULT = 5
	AGENT_POLL_ENVOY_READINESS_TIMEOUT_S_DEFAULT  = 180

	ENABLE_STATS_SNAPSHOT_DEFAULT = false

	ENVOY_SERVER_SCHEME                  = "http"
	ENVOY_SERVER_HOSTNAME                = "127.0.0.1"
	ENVOY_RESTART_COUNT_DEFAULT          = 0
	ENVOY_RESTART_COUNT_MAX              = 10
	ENVOY_ADMIN_PORT_DEFAULT             = 9901
	ENVOY_ADMIN_MODE_DEFAULT             = "tcp"
	ENVOY_ADMIN_UDS_PATH                 = "/tmp/envoy_admin.sock"
	ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT    = 384 // decimal form of file permission 0600 (octal)
	ENVOY_READY_ENDPOINT_URL             = "/ready"
	ENVOY_STATS_ENDPOINT_URL             = "/stats"
	ENVOY_LOGGING_ENDPOINT_URL           = "/logging"
	ENVOY_PROMETHEUS_QUERY_STRING        = "?format=prometheus"
	APPMESH_FILTER_STRING                = "filter=appmesh"
	ENVOY_LISTENER_DRAINING_ENDPOINT_URL = "/drain_listeners"
	ENVOY_CONCURRENCY_DEFAULT            = -1  // we will not set concurrency [envoy --concurrency] by default.
	ENVOY_CONCURRENCY_FOR_RELAY_DEFAULT  = "1" // For relay we are defaulting it to 1

	// agent relay mode
	ENABLE_RELAY_MODE_FOR_XDS_DEFAULT      = false
	APPNET_RELAY_LISTENER_UDS_PATH_DEFAULT = "/tmp/relay_xds.sock"
	RELAY_STREAM_IDLE_TIMEOUT_DEFAULT      = "2400s"  // Default is set to 40 min, whereas Envoy default is 5 min.
	RELAY_BUFFER_LIMIT_BYTES_DEFAULT       = 10485760 // Default is set to 10MB, whereas Envoy default is 1 MB.
	APPNET_MANAGEMENT_PORT_DEFAULT         = 443

	// agent handled endpoints
	AGENT_STATS_ENDPOINT_URL          = "/stats/prometheus"
	AGENT_STATUS_ENDPOINT_URL         = "/status"
	AGENT_LISTENER_DRAIN_ENDPOINT_URL = "/drain_listeners"
	APPNET_USER_AGENT                 = "appnetClient/1.0"
	AGENT_LOGGING_ENDPOINT_URL        = "/enableLogging"
	AGENT_LOG_IDENTIFIER              = "AppNet Agent"

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
	// See https://sim.amazon.com/issues/LATTICE-BE-6236
	// We are reducing the frequency to poll health check
	HC_POLL_INTERVAL_MS_DEFAULT       = 10000
	HC_POLL_INTERVAL_MS_MIN           = 2000
	HC_POLL_INTERVAL_MS_MAX           = 30000
	HC_DISCONNECTED_TIMEOUT_S_DEFAULT = 604800 // 1 week
	HC_DISCONNECTED_TIMEOUT_S_MIN     = 3600
	HC_DISCONNECTED_TIMEOUT_S_MAX     = 604800

	// ECS stopTimeout is 30sec by default and can be set to maximum 120sec
	LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT = 20
	LISTENER_DRAIN_WAIT_TIME_SEC_MIN     = 5
	LISTENER_DRAIN_WAIT_TIME_SEC_MAX     = 110
	// Wait 3 seconds for Envoy to exit, before we kill it
	PID_STOP_DELAY_SEC = 3

	AGENT_ADDRESS_DEFAULT = "[::]"

	AGENT_LOGGING_RESET_TIMEOUT_S_DEFAULT = 300

	// Rate limiter constants
	TPS_LIMIT       = 10
	BURST_TPS_LIMIT = 20
)

var AdminModeStrToEnumMap = map[string]SocketType{
	"uds": UDS,
	"tcp": TCP,
}

type AgentConfig struct {
	CommandPath                     string
	CommandArgs                     []string
	AgentHttpPort                   int
	AgentHttpAddress                string
	AgentAdminUdsPath               string
	AgentAdminMode                  SocketType
	AgentLoglevelReset              time.Duration
	AgentPollEnvoyReadiness         bool
	AgentPollEnvoyReadinessInterval int
	AgentPollEnvoyReadinessTimeout  int
	EnvoyRestartCount               int
	EnvoyServerScheme               string
	EnvoyServerHostName             string
	EnvoyServerAdminPort            int
	EnvoyServerAdminUdsPath         string
	EnvoyAdminMode                  SocketType
	EnvoyReadyUrl                   string
	EnvoyServerStatsUrl             string
	EnableStatsSnapshot             bool
	EnvoyListenerDrainUrl           string
	EnvoyLoggingUrl                 string
	EnvoyLoggingDestination         string
	EnvoyLogFileName                string
	EnvoyLogLevel                   string
	EnvoyConfigPath                 string
	EnvoyConcurrency                int
	ClusterIPMapping                string
	ListenerPortMapping             string
	MaxLogFileSizeMB                float64
	MaxLogCount                     int

	XdsEndpointUdsPath string

	// Relay Mode
	EnableRelayModeForXds      bool
	AppNetManagementDomainName string
	AppNetManagementPort       int
	AppNetRelayListenerUdsPath string
	RelayStreamIdleTimeout     string
	RelayBufferLimitBytes      int

	// Poll intervals
	PidPollInterval       time.Duration
	HcPollInterval        time.Duration
	HcDisconnectedTimeout time.Duration
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

func getEnvValueAsIntNoDefault(varName string) (int, error) {

	value, exists := os.LookupEnv(varName)
	if !exists {
		return 0, fmt.Errorf("Environment variable %s does not exist.", varName)
	}

	envValue, err := strconv.Atoi(value)
	if err != nil {
		log.Debugf("Unable to get a usable integer value from environment variable [%s]\n", varName)
		return 0, fmt.Errorf("Unable to get a usable integer value from environment variable [%s]\n", varName)
	}

	return envValue, nil
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

func getEnvValueAsBool(varName string, defaultValue bool) bool {

	value, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue
	}

	envValue, err := strconv.ParseBool(value)
	if err != nil {
		log.Debugf("Unable to get a usable bool value from environment variable [%s]\n", varName)
		return defaultValue
	}

	return envValue
}

func getAdminModeFromEnv(adminModeEnvName string, defaultAdminModeEnvValue string) SocketType {
	// get AdminMode Enum for adminModeEnvName: {AGENT_ADMIN_MODE, ENVOY_ADMIN_MODE}
	adminModeStr := strings.ToLower(getEnvValueAsString(adminModeEnvName, defaultAdminModeEnvValue))
	if adminModeEnum, mapContainsKey := AdminModeStrToEnumMap[adminModeStr]; mapContainsKey {
		return adminModeEnum
	}
	return AdminModeStrToEnumMap[defaultAdminModeEnvValue]
}

func dumpAllEnvVariables() {
	// Retrieve all environment variables
	envVariables := os.Environ()

	appMeshVar := make([]string, 0)
	envoyVar := make([]string, 0)
	agentVar := make([]string, 0)

	// Filter all variables by their prefix
	for _, envVar := range envVariables {
		if strings.HasPrefix(envVar, "ENVOY_") {
			envoyVar = append(envoyVar, envVar)
		} else if strings.HasPrefix(envVar, "APPMESH_") {
			appMeshVar = append(appMeshVar, envVar)
		} else if strings.HasPrefix(envVar, "APPNET_") {
			agentVar = append(agentVar, envVar)
		}
	}

	log.Infof("App Mesh Environment Variables: %v", appMeshVar)
	log.Infof("Envoy Environment Variables: %v", envoyVar)
	log.Infof("Agent Environment Variables: %v", agentVar)
}

func getDefaultBootstrapFilePath() string {

	tmpFile, err := ioutil.TempFile(os.TempDir(), "envoy-config-*.yaml")
	if err != nil {
		log.Errorf("Cannot create bootstrap file. %v", err)
	}
	return tmpFile.Name()
}

// We set the health check poll interval honoring following precedence
// - HC_POLL_INTERVAL_MS
// - APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S
// - HC_POLL_INTERVAL_MS_DEFAULT
func getHcPollInterval() time.Duration {
	hcPollInterval, err := getEnvValueAsIntNoDefault("HC_POLL_INTERVAL_MS")
	if err == nil {
		return time.Duration(hcPollInterval) * time.Millisecond
	}

	if hcPollInterval, err = getEnvValueAsIntNoDefault("APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S"); err == nil {
		return time.Duration(hcPollInterval) * time.Second
	}

	return time.Duration(HC_POLL_INTERVAL_MS_DEFAULT) * time.Millisecond
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

	if config.HcDisconnectedTimeout < HC_DISCONNECTED_TIMEOUT_S_MIN*time.Second {
		log.Warnf("HC_DISCONNECTED_TIMEOUT_S cannot be less than %ds, setting it to %ds as a default",
			HC_DISCONNECTED_TIMEOUT_S_MIN, HC_DISCONNECTED_TIMEOUT_S_DEFAULT)
		config.HcDisconnectedTimeout = HC_DISCONNECTED_TIMEOUT_S_DEFAULT * time.Second
	}

	if config.HcDisconnectedTimeout > HC_DISCONNECTED_TIMEOUT_S_MAX*time.Second {
		log.Warnf("HC_DISCONNECTED_TIMEOUT_S cannot be greater than %ds, setting it to %ds as a default",
			HC_DISCONNECTED_TIMEOUT_S_MAX, HC_DISCONNECTED_TIMEOUT_S_DEFAULT)
		config.HcDisconnectedTimeout = HC_DISCONNECTED_TIMEOUT_S_DEFAULT * time.Second
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

// validate that the log level is a known value otherwise use the default
func validateEnvoyLogLevel(logLevel *string) {

	switch *logLevel {
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
		*logLevel = "info"
	}

}

func (config *AgentConfig) ParseFlags(args []string) {
	// Define command line flags that must be supplied
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)

	envConfigFile := getEnvValueAsString("ENVOY_CONFIG_FILE", "")
	flags.StringVar(&config.EnvoyConfigPath, "envoyConfigPath", envConfigFile, "envoy bootstrap config path")

	// Unless specified as a parameter to the agent use ENVOY_LOG_LEVEL
	defaultLogLevel := strings.ToLower(getEnvValueAsString("ENVOY_LOG_LEVEL", "info"))
	flags.StringVar(&config.EnvoyLogLevel, "logLevel", defaultLogLevel, "the log level (e.g. debug, info)")
	flags.BoolVar(&config.AgentPollEnvoyReadiness, "envoyReadiness", false, "poll envoy is ready")

	flags.Parse(args[1:])
}

func (config *AgentConfig) SetDefaults() {

	config.CommandPath = "/usr/bin/envoy"

	dumpAllEnvVariables()

	// Ensure port value is > 1024 if uid != 0.  Ensure port is less than 65535
	config.AgentHttpPort = getEnvValueAsInt("APPNET_AGENT_HTTP_PORT", AGENT_PORT_DEFAULT)
	if config.AgentHttpPort > 65535 || (os.Geteuid() != 0 && config.AgentHttpPort < 1024) {
		log.Warnf("Invalid value [%d] for the Agent Management port value. Using the default [%d]",
			config.AgentHttpPort,
			AGENT_PORT_DEFAULT)
		config.AgentHttpPort = AGENT_PORT_DEFAULT
	}

	// xDS Relay
	config.EnableRelayModeForXds = getEnvValueAsBool("APPNET_ENABLE_RELAY_MODE_FOR_XDS", ENABLE_RELAY_MODE_FOR_XDS_DEFAULT)
	if config.EnableRelayModeForXds {
		config.AppNetRelayListenerUdsPath = getEnvValueAsString("APPNET_RELAY_LISTENER_UDS_PATH", APPNET_RELAY_LISTENER_UDS_PATH_DEFAULT)
		config.AppNetManagementPort = getEnvValueAsInt("APPNET_MANAGEMENT_PORT", APPNET_MANAGEMENT_PORT_DEFAULT)
		config.RelayStreamIdleTimeout = getEnvValueAsString("RELAY_STREAM_IDLE_TIMEOUT", RELAY_STREAM_IDLE_TIMEOUT_DEFAULT)
		config.RelayBufferLimitBytes = getEnvValueAsInt("RELAY_BUFFER_LIMIT_BYTES", RELAY_BUFFER_LIMIT_BYTES_DEFAULT)

		xdsDomain := getEnvValueAsString("APPMESH_XDS_ENDPOINT", "")
		if strings.HasPrefix(xdsDomain, URL_HTTP_SCHEME) {
			config.AppNetManagementDomainName = strings.Replace(xdsDomain, URL_HTTP_SCHEME, "", 1)
		} else if strings.HasPrefix(xdsDomain, URL_HTTPS_SCHEME) {
			config.AppNetManagementDomainName = strings.Replace(xdsDomain, URL_HTTPS_SCHEME, "", 1)
		} else {
			config.AppNetManagementDomainName = xdsDomain
		}
	}

	config.AgentAdminMode = getAdminModeFromEnv("APPNET_AGENT_ADMIN_MODE", AGENT_ADMIN_MODE_DEFAULT)
	if config.AgentAdminMode == UDS {
		config.AgentAdminUdsPath = getEnvValueAsString("APPNET_AGENT_ADMIN_UDS_PATH", AGENT_ADMIN_UDS_PATH_DEFAULT)
	}
	config.EnvoyAdminMode = getAdminModeFromEnv("ENVOY_ADMIN_MODE", ENVOY_ADMIN_MODE_DEFAULT)

	config.AgentPollEnvoyReadinessInterval = getEnvValueAsInt("APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S", AGENT_POLL_ENVOY_READINESS_INTERVAL_S_DEFAULT)
	config.AgentPollEnvoyReadinessTimeout = getEnvValueAsInt("APPNET_AGENT_POLL_ENVOY_READINESS_TIMEOUT_S", AGENT_POLL_ENVOY_READINESS_TIMEOUT_S_DEFAULT)

	// TODO: Ensure that configured address exists on hosts if it is not "0.0.0.0" or "127.0.0.1"
	config.AgentHttpAddress = getEnvValueAsString("APPNET_AGENT_HTTP_BIND_ADDRESS", AGENT_ADDRESS_DEFAULT)

	config.EnvoyRestartCount = getEnvValueAsInt("APPNET_ENVOY_RESTART_COUNT", ENVOY_RESTART_COUNT_DEFAULT)

	config.AgentLoglevelReset = time.Duration(
		getEnvValueAsInt("APPNET_AGENT_LOGGING_RESET_TIMEOUT", AGENT_LOGGING_RESET_TIMEOUT_S_DEFAULT)) * time.Second

	config.EnvoyServerScheme = ENVOY_SERVER_SCHEME
	config.EnvoyServerHostName = ENVOY_SERVER_HOSTNAME

	config.EnvoyServerAdminPort = getEnvValueAsInt("ENVOY_ADMIN_ACCESS_PORT", ENVOY_ADMIN_PORT_DEFAULT)
	config.EnvoyReadyUrl = ENVOY_READY_ENDPOINT_URL
	config.EnvoyServerStatsUrl = ENVOY_STATS_ENDPOINT_URL
	config.EnvoyLoggingUrl = ENVOY_LOGGING_ENDPOINT_URL
	config.EnvoyListenerDrainUrl = ENVOY_LISTENER_DRAINING_ENDPOINT_URL
	if config.EnvoyAdminMode == UDS {
		config.EnvoyServerAdminUdsPath = ENVOY_ADMIN_UDS_PATH
	}

	config.EnableStatsSnapshot = getEnvValueAsBool("ENABLE_STATS_SNAPSHOT", ENABLE_STATS_SNAPSHOT_DEFAULT)

	xdsEndpoint := getEnvValueAsString("APPMESH_XDS_ENDPOINT", "")
	if strings.HasPrefix(xdsEndpoint, URI_UNIX_PREFIX) {
		config.XdsEndpointUdsPath = xdsEndpoint
		// verify that the uds path specified exists
		xdsUnixPath := strings.Replace(xdsEndpoint, URI_UNIX_PREFIX, "", -1)
		if _, err := os.Stat(xdsUnixPath); err != nil {
			log.Warnf("xDS endpoint UDS path does not exist: %v", err)
		}
	}

	// Logging
	config.EnvoyLoggingDestination = getEnvValueAsString("APPNET_ENVOY_LOG_DESTINATION", ENVOY_LOG_DESTINATION_DEFAULT)
	config.EnvoyLogFileName = getEnvValueAsString("APPNET_ENVOY_LOG_NAME", ENVOY_LOG_FILE_NAME_DEFAULT)

	config.MaxLogFileSizeMB = getEnvValueAsFloat("APPNET_AGENT_MAX_LOG_FILE_SIZE", AGENT_MAX_LOG_FILE_SIZE_DEFAULT)
	config.MaxLogCount = getEnvValueAsInt("APPNET_AGENT_MAX_RETENTION_COUNT", AGENT_MAX_LOG_RETENTION_DEFAULT)
	if config.EnvoyConfigPath == "" {
		config.EnvoyConfigPath = getEnvValueAsString("ENVOY_CONFIG_FILE", getDefaultBootstrapFilePath())
	}

	config.EnvoyConcurrency = getEnvValueAsInt("ENVOY_CONCURRENCY", ENVOY_CONCURRENCY_DEFAULT)

	validateEnvoyLogLevel(&config.EnvoyLogLevel)

	// We expect this to be populated with a json string
	config.ClusterIPMapping = getEnvValueAsString("APPNET_CONTAINER_IP_MAPPING", "")
	config.ListenerPortMapping = getEnvValueAsString("APPNET_LISTENER_PORT_MAPPING", "")

	// Timers
	config.PidPollInterval = time.Duration(
		getEnvValueAsInt("PID_POLL_INTERVAL_MS", PID_POLL_INTERVAL_MS_DEFAULT)) * time.Millisecond
	config.HcPollInterval = getHcPollInterval()
	config.ListenerDrainWaitTime = time.Duration(
		getEnvValueAsInt("LISTENER_DRAIN_WAIT_TIME_S", LISTENER_DRAIN_WAIT_TIME_SEC_DEFAULT)) * time.Second
	config.HcDisconnectedTimeout = time.Duration(
		getEnvValueAsInt("HC_DISCONNECTED_TIMEOUT_S", HC_DISCONNECTED_TIMEOUT_S_DEFAULT)) * time.Second
	validateTimers(config)
}
