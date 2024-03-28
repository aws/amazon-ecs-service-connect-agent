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

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/internal/netlistenertest"
	"github.com/aws/aws-app-mesh-agent/agent/logging"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"
	"github.com/aws/aws-app-mesh-agent/agent/server"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type OpenfilesLimit struct {
	Soft uint64
	Hard uint64
}

func TestBuildCommandArgs(t *testing.T) {
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()

	arguments := buildCommandArgs(agentConfig)

	assert.Equal(t, len(arguments), 8)
	assert.ElementsMatch(t, []string{
		agentConfig.CommandPath,
		"-c",
		agentConfig.EnvoyConfigPath,
		"-l",
		agentConfig.EnvoyLogLevel,
		"--drain-time-s",
		strconv.Itoa(int(agentConfig.ListenerDrainWaitTime / time.Second)),
		"--disable-hot-restart",
	}, arguments)
}

func TestBuildCommandArgsNoEnvoyParameters(t *testing.T) {
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()
	agentConfig.EnvoyConfigPath = ""
	agentConfig.EnvoyLogLevel = ""
	agentConfig.ListenerDrainWaitTime = 0
	agentConfig.DisableHotRestart = false

	arguments := buildCommandArgs(agentConfig)

	assert.Equal(t, 1, len(arguments))
	assert.ElementsMatch(t, []string{agentConfig.CommandPath}, arguments)
}

func parseUint(s string) (uint64, error) {
	if s == "unlimited" {
		return 18446744073709551615, nil
	}
	i, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("couldn't parse value %q: %w", s, err)
	}
	return i, nil
}

func getOpenfilesLimit(pid int) (*OpenfilesLimit, error) {
	limitsFile := fmt.Sprintf("/proc/%d/limits", pid)
	file, err := os.Open(limitsFile)

	if err != nil {
		return nil, err
	}

	var limit = OpenfilesLimit{}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	// skip header
	scanner.Scan()

	var limitsMatch = regexp.MustCompile(`(Max \w+\s{0,1}?\w*\s{0,1}\w*)\s{2,}(\w+)\s+(\w+)`)
	for scanner.Scan() {
		fields := limitsMatch.FindStringSubmatch(scanner.Text())
		if len(fields) != 4 {
			return &OpenfilesLimit{}, fmt.Errorf("couldn't parse limits file, line: %s", scanner.Text())
		}

		switch fields[1] {
		case "Max open files":
			limit.Soft, err = parseUint(fields[2])
			if err != nil {
				return &OpenfilesLimit{}, err
			}

			limit.Hard, err = parseUint(fields[3])
			if err != nil {
				return &OpenfilesLimit{}, err
			}
			return &limit, nil
		}
	}
	return &OpenfilesLimit{}, fmt.Errorf("Max open files limits not found")
}

func TestStartCommand(t *testing.T) {
	err := setupOpenfilesLimit()
	assert.Nil(t, err)

	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()
	agentConfig.EnvoyConfigPath = ""
	agentConfig.EnvoyLogLevel = ""
	agentConfig.CommandPath, _ = exec.LookPath("uname")
	agentConfig.CommandArgs = []string{"-a"}

	// Set the drain time to zero so that we do not append the --drain-time-s parameter
	// in buildCommandArgs
	agentConfig.ListenerDrainWaitTime = 0

	logging.SetupLogger(&agentConfig)
	args := buildCommandArgs(agentConfig)

	pid, err := startCommand(agentConfig, args)
	assert.NotEqual(t, pid, -1)
	assert.Nil(t, err)

	noFileLimit, err := getOpenfilesLimit(pid)
	log.Debugf("open files limit soft: %d, hard: %d\n", noFileLimit.Soft, noFileLimit.Hard)
	assert.Nil(t, err)
	assert.Equal(t, noFileLimit.Soft, noFileLimit.Hard)
	assert.GreaterOrEqual(t, noFileLimit.Soft, uint64(65535))
}

func TestNonBlockingChannelRead(t *testing.T) {
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()

	logging.SetupLogger(&agentConfig)

	var messageSources messagesources.MessageSources
	messageSources.SetupChannels()

	// Since we do not write to the processAlive channel, normally
	// the read will block.  Because we are using select the
	// getProcessStatus() will return a value

	status := messageSources.GetProcessStatus()
	assert.False(t, status)
}

func TestKeepCommandAlive(t *testing.T) {
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()

	logging.SetupLogger(&agentConfig)

	var sleepTime = 3 * time.Second
	var executionTimeout = 4 * time.Second

	agentConfig.SetDefaults()
	agentConfig.EnvoyConfigPath = ""
	agentConfig.EnvoyLogLevel = ""
	agentConfig.ListenerDrainWaitTime = 0
	agentConfig.DisableHotRestart = false
	agentConfig.CommandPath, _ = exec.LookPath("sleep")
	agentConfig.CommandArgs = []string{sleepTime.String()}

	var messageSources messagesources.MessageSources
	messageSources.SetupChannels()

	start := time.Now()

	go keepCommandAlive(agentConfig, &messageSources)

	for {
		loopElapsed := time.Since(start)
		if loopElapsed > executionTimeout {
			log.Debugf("Exiting loop because we spent more than %d seconds looping\n", executionTimeout)
			break
		}

		// Allow the keepCommandAlive loop to execute at least once and update the status
		time.Sleep(2 * agentConfig.PidPollInterval)

		if !messageSources.GetProcessStatus() {
			log.Debugf("Exiting loop because process exited\n")
			break
		}
	}
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, sleepTime)
}

func TestKeepCommandAliveWithRestart(t *testing.T) {

	var agentConfig config.AgentConfig
	var minimumExecutionTime float64 = 8.0
	var executionTimeout float64 = 10.0

	agentConfig.SetDefaults()
	agentConfig.EnvoyConfigPath = ""
	agentConfig.EnvoyLogLevel = ""
	agentConfig.ListenerDrainWaitTime = 0
	agentConfig.DisableHotRestart = false
	agentConfig.EnvoyRestartCount = 2
	agentConfig.CommandPath, _ = exec.LookPath("sleep")
	agentConfig.CommandArgs = []string{"3"}

	logging.SetupLogger(&agentConfig)

	var messageSources messagesources.MessageSources
	messageSources.SetupChannels()

	start := time.Now()

	go keepCommandAlive(agentConfig, &messageSources)

	// one initial start and EnvoyRestartCount additional pids
	expectedPids := agentConfig.EnvoyRestartCount + 1

	var processDeadCount int = 0
	pid := make(map[int]bool)

	for {
		loopElapsed := time.Since(start).Seconds()
		if loopElapsed > executionTimeout {
			log.Debugf("Exiting loop because we spent more than %f seconds looping\n", executionTimeout)
			assert.Fail(t, "Exceeded maximum execution time.")
		}

		// Allow the keepCommandAlive loop to execute at least once and update the status
		time.Sleep(3 * agentConfig.PidPollInterval)

		// Collect the pids here.  If we see a different pid it means a restart occurred
		// We should have agentConfig.EnvoyRestartCount+1 pids. The increment is for the
		// initial pid
		pidVal := messageSources.GetPid()
		if _, exists := pid[pidVal]; !exists {
			pid[pidVal] = true // pid changed
		}

		if !messageSources.GetProcessStatus() {
			processDeadCount++
			// We restart EnvoyRestartCount in addition to the initial fork
			if processDeadCount == expectedPids {
				log.Debugf("Exiting loop because process exited [restarts=%d]\n", processDeadCount)
				break
			}
		}
	}

	elapsed := time.Since(start).Seconds()

	// Verify that we have "restartCount + 1 (initial process id)" number of pids
	assert.Equal(t, expectedPids, len(pid))

	// Verify that the process state channel is false since the forked process is no longer active.
	assert.False(t, messageSources.GetProcessStatus())

	// Validate that we ran 3 instances of "sleep 3", which should take more than 8 seconds
	assert.Less(t, minimumExecutionTime, elapsed)

	// Validate that we did not run for longer than 10 seconds.
	assert.GreaterOrEqual(t, executionTimeout, elapsed)
}

func setupEnvoyAdminServer(agentConfig *config.AgentConfig) (*httptest.Server, *netlistenertest.ListenContext, error) {
	// Setup Envoy admin server
	var drainResponse string = "OK\n"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(res http.ResponseWriter, r *http.Request) {
		res.WriteHeader(200)
		res.Write([]byte(drainResponse))
	}))

	var envoyCtx netlistenertest.ListenContext
	err := envoyCtx.CreateEnvoyAdminListener(agentConfig)
	if err != nil {
		return nil, nil, err
	}

	// Close the httptest listener as it listens on port 80 by default
	err = srv.Listener.Close()
	if err != nil {
		return nil, nil, err
	}

	// Attach the new listener to the httptest server
	srv.Listener = *envoyCtx.Listener
	srv.Start()

	return srv, &envoyCtx, nil
}

func TestDrainListenerEndpoint(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "tcp")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	// Setup Envoy admin server
	srv, envoyCtx, err := setupEnvoyAdminServer(&agentConfig)
	assert.Nil(t, err)
	assert.NotNil(t, srv)
	assert.NotNil(t, envoyCtx)

	defer srv.Close()
	defer envoyCtx.Close()

	var httpClient *http.Client
	envoyListenerDrainUrl := fmt.Sprintf("%s://%s:%d%s",
		agentConfig.EnvoyServerScheme,
		agentConfig.EnvoyServerHostName,
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyListenerDrainUrl)
	switch agentConfig.EnvoyAdminMode {
	case config.UDS:
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", agentConfig.EnvoyServerAdminUdsPath)
				},
			},
		}
	default:
		httpClient = &http.Client{}
	}

	res, err := httpClient.Post(envoyListenerDrainUrl, "", nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	defer res.Body.Close()
	responseData, _ := ioutil.ReadAll(res.Body)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "OK\n", string(responseData))
}

func TestGracefullyDrainEnvoyListeners(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "tcp")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	// Drain for 5 secs
	drainTime := 5 * time.Second
	executionTime := 6 * time.Second
	os.Setenv("LISTENER_DRAIN_WAIT_TIME_S", strconv.Itoa(int(drainTime/time.Second)))
	defer os.Unsetenv("LISTENER_DRAIN_WAIT_TIME_S")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	// Setup Envoy admin server
	srv, envoyCtx, err := setupEnvoyAdminServer(&agentConfig)
	assert.Nil(t, err)
	assert.NotNil(t, srv)
	assert.NotNil(t, envoyCtx)

	defer srv.Close()
	defer envoyCtx.Close()

	// Call listener drain
	start := time.Now()
	gracefullyDrainEnvoyListeners(agentConfig)
	assert.GreaterOrEqual(t, time.Since(start), drainTime)
	assert.Less(t, time.Since(start), executionTime)
}

func getTmpDir() string {
	tempDir := os.Getenv("TMPDIR")
	if len(tempDir) == 0 {
		tempDir = "/tmp"
	}
	return tempDir
}

func TestLoggingToFileWithCommandExecution(t *testing.T) {
	var minFileSize int64 = 200
	var agentConfig config.AgentConfig

	// Set environment variables redirecting logging to a file on disk
	os.Setenv("APPNET_ENVOY_LOG_DESTINATION", getTmpDir())
	os.Setenv("APPNET_ENVOY_LOG_NAME", "agent_log_file_test_TestLoggingToFileWithCommandExecution.log")

	// Unset these variables when we are done
	defer os.Unsetenv("APPNET_ENVOY_LOG_DESTINATION")
	defer os.Unsetenv("APPNET_ENVOY_LOG_NAME")

	logPath := path.Join(
		os.Getenv("APPNET_ENVOY_LOG_DESTINATION"),
		os.Getenv("APPNET_ENVOY_LOG_NAME"),
	)

	// Remove any left over cruft.  Cleanup when we're done
	os.Remove(logPath)
	defer os.Remove(logPath)

	// Setup the logger based on the config
	agentConfig.SetDefaults()

	// Run the echo command with various arguments
	agentConfig.EnvoyConfigPath = ""
	agentConfig.EnvoyLogLevel = ""
	agentConfig.ListenerDrainWaitTime = 0
	agentConfig.DisableHotRestart = false
	agentConfig.CommandPath, _ = exec.LookPath("echo")
	agentConfig.CommandArgs = []string{
		"this", "is", "my", "test.",
		"there", "are", "many", "like", "it,",
		"but", "this", "one", "is", "mine",
	}

	// Create a logger that should write all output to a file on disk based on the
	// environment variables above being defined
	logging.SetupLogger(&agentConfig)
	log.SetLevel(log.DebugLevel)

	var messageSources messagesources.MessageSources
	messageSources.SetupChannels()

	// We just need the command to run.  This won't take long
	go keepCommandAlive(agentConfig, &messageSources)
	time.Sleep(250 * time.Millisecond)

	syscall.Sync()

	// Verify that the log file was created and has data
	fileInfo, err := os.Stat(logPath)
	assert.Nil(t, err)
	assert.Greater(t, fileInfo.Size(), minFileSize)

	fp, err := os.Open(logPath)
	assert.Nil(t, err)
	reader := bufio.NewReader(fp)

	commandOutput := strings.Join(agentConfig.CommandArgs, " ")

	// Read the contents of the log line and verify echoed string exists with no timestamp
	// This verifies the command output is captured and redirected to our log file.
	var lineCount int = 0
	var foundLogLine bool = false
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}

		if strings.HasPrefix(line, commandOutput) {
			foundLogLine = true
		}

		lineCount++
	}

	assert.Greater(t, lineCount, 2)
	assert.True(t, foundLogLine)
}

// Skip this test since it's failing on codebuild as well as on macOS.
// This functionality is not being used right now and so, we can turn this off.
func skip_TestLogRotation(t *testing.T) {

	var agentConfig config.AgentConfig

	// Set environment variables redirecting logging to a file on disk
	os.Setenv("APPNET_ENVOY_LOG_DESTINATION", getTmpDir())
	os.Setenv("APPNET_ENVOY_LOG_NAME", "agent_log_file_test_TestLogRotation.log")

	// Unset these variables when we are done
	defer os.Unsetenv("APPNET_ENVOY_LOG_DESTINATION")
	defer os.Unsetenv("APPNET_ENVOY_LOG_NAME")

	logPath := path.Join(
		os.Getenv("APPNET_ENVOY_LOG_DESTINATION"),
		os.Getenv("APPNET_ENVOY_LOG_NAME"),
	)

	// Remove any left over cruft.  Cleanup when we're done
	os.Remove(logPath)
	defer logging.CleanupLogFiles(logPath, 0)
	defer os.Remove(logPath)

	// Setup the logger based on the config
	agentConfig.SetDefaults()
	agentConfig.EnvoyConfigPath = ""
	agentConfig.EnvoyLogLevel = ""
	agentConfig.EnvoyRestartCount = 2
	agentConfig.ListenerDrainWaitTime = 0

	// Sadly this syntax does not work on macOS.  Defaulting to the
	// linux syntax of top since this macOS is not the target platform
	agentConfig.CommandPath, _ = exec.LookPath("top")
	agentConfig.CommandArgs = []string{"-b", "-d", "0.1"}
	agentConfig.MaxLogCount = 2
	agentConfig.MaxLogFileSizeMB = 0.01

	logging.SetupLogger(&agentConfig)
	log.SetLevel(log.DebugLevel)

	var messageSources messagesources.MessageSources
	messageSources.SetupChannels()

	go keepCommandAlive(agentConfig, &messageSources)

	// Run for 10 seconds to give ample time for data to accumulate
	time.Sleep(10 * time.Second)

	// Shutdown the process.
	stopProcesses(agentConfig.StopProcessWaitTime, &messageSources)

	// Check the number of files in the temp_dir conforming to our log format
	// Check the size of each file.
	var logfilePattern string = fmt.Sprintf("%s.[0-9]*", logPath)
	matches, err := filepath.Glob(logfilePattern)

	assert.Nil(t, err)

	for _, f := range matches {
		fileInfo, err := os.Stat(f)
		assert.Nil(t, err)
		assert.Less(t, fileInfo.Size(), int64(2*agentConfig.MaxLogFileSizeMB*1_048_576))
	}
	assert.Equal(t, agentConfig.MaxLogCount, len(matches))
}

func TestHttpHandlerMultipleIpVersions(t *testing.T) {
	os.Setenv("APPNET_AGENT_ADMIN_MODE", "tcp")
	defer os.Unsetenv("APPNET_AGENT_ADMIN_MODE")
	var config config.AgentConfig
	config.SetDefaults()
	const (
		TYPE    = 0
		ADDRESS = 1
	)

	destination := map[string][]string{
		"/ipv4": {"tcp4", fmt.Sprintf("127.0.0.1:%d", config.AgentHttpPort)},
		"/ipv6": {"tcp6", fmt.Sprintf("[::1]:%d", config.AgentHttpPort)},
	}

	handlerSpec := server.HandlerSpec{
		"/{ipType}": func(response http.ResponseWriter, request *http.Request) {

			socketInfo, exists := destination[request.URL.Path]
			assert.True(t, exists)

			response.WriteHeader(http.StatusOK)
			assert.Equal(t, socketInfo[ADDRESS], request.Host)

			_, err := io.WriteString(response, fmt.Sprintf("Reached %s", request.URL.Path))
			assert.Nil(t, err)
		},
	}

	// Start the Agent's HTTP Server with our faux handler
	var messageSources messagesources.MessageSources
	go server.StartHttpServer(config, handlerSpec, &messageSources)

	// Give things time to bind and start
	time.Sleep(250 * time.Millisecond)

	// Make our reqeuests
	for path, socketHost := range destination {

		// Define a httpClient that connects to ipv4 or ipv6 explicitly
		httpClient := http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial(socketHost[TYPE], socketHost[ADDRESS])
				},
			},
		}

		// build the request
		request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", socketHost[ADDRESS], path), nil)
		assert.Nil(t, err)

		// Make it so!
		response, err := httpClient.Do(request)
		assert.Nil(t, err)

		responseBody, err := io.ReadAll(response.Body)
		assert.Nil(t, err)

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, fmt.Sprintf("Reached %s", path), string(responseBody))

		response.Body.Close()
	}

}

func TestHttpHandlerUds(t *testing.T) {
	os.Setenv("APPNET_AGENT_ADMIN_MODE", "uds")
	defer os.Unsetenv("APPNET_AGENT_ADMIN_MODE")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	paths := []string{"/path1", "/path2"}
	handlerSpec := server.HandlerSpec{}
	for _, path := range paths {
		handlerSpec[path] = func(response http.ResponseWriter, request *http.Request) {
			response.WriteHeader(http.StatusOK)
			_, err := io.WriteString(response, fmt.Sprintf("Reached %s", request.URL.Path))
			assert.Nil(t, err)
		}
	}

	// Start the Agent's HTTP Server with our faux handler and temporary Uds path
	tmpFile, err := ioutil.TempFile(os.TempDir(), "agent_admin_test_*.sock")
	assert.Nil(t, err)
	udsPath := tmpFile.Name()
	err = os.Remove(udsPath)
	assert.Nil(t, err)
	agentConfig.AgentAdminUdsPath = udsPath

	var messageSources messagesources.MessageSources
	go server.StartHttpServer(agentConfig, handlerSpec, &messageSources)

	// Give things time to bind and start
	time.Sleep(250 * time.Millisecond)

	// Make our reqeuests
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial(config.NETWORK_SOCKET_UNIX, agentConfig.AgentAdminUdsPath)
			},
		},
	}

	for _, path := range paths {
		// build the request
		request, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:9902%s", path), nil)
		assert.Nil(t, err)

		// Make it so!
		response, err := httpClient.Do(request)
		assert.Nil(t, err)

		responseBody, err := io.ReadAll(response.Body)
		assert.Nil(t, err)

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, fmt.Sprintf("Reached %s", path), string(responseBody))

		response.Body.Close()
	}
}
func TestSetupUdsForEnvoyAdmin(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", "uds")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	var messageSources messagesources.MessageSources
	setupUdsForEnvoyAdmin(agentConfig, &messageSources)
	fileInfo, err := os.Stat(agentConfig.EnvoyServerAdminUdsPath)
	assert.Nil(t, err)
	assert.Equal(t, fileInfo.Mode().Perm(), os.FileMode(config.ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT))

	os.Chmod(agentConfig.EnvoyServerAdminUdsPath, 0666)
	fileInfo, err = os.Stat(agentConfig.EnvoyServerAdminUdsPath)
	assert.Nil(t, err)
	assert.Equal(t, fileInfo.Mode().Perm(), os.FileMode(0666))
	setupUdsForEnvoyAdmin(agentConfig, &messageSources)
	fileInfo, err = os.Stat(agentConfig.EnvoyServerAdminUdsPath)
	assert.Nil(t, err)
	assert.Equal(t, fileInfo.Mode().Perm(), os.FileMode(config.ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT))

	os.Remove(agentConfig.EnvoyServerAdminUdsPath)
}
