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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/logging"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestBuildCommandArgs(t *testing.T) {
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()

	arguments := buildCommandArgs(agentConfig)

	assert.Equal(t, len(arguments), 7)
	assert.ElementsMatch(t, []string{
		agentConfig.CommandPath,
		"-c",
		*agentConfig.EnvoyConfigPath,
		"-l",
		*agentConfig.EnvoyLogLevel,
		"--drain-time-s",
		strconv.Itoa(int(agentConfig.ListenerDrainWaitTime / time.Second)),
	}, arguments)
}

func TestBuildCommandArgsNoEnvoyParameters(t *testing.T) {
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()
	agentConfig.EnvoyConfigPath = nil
	agentConfig.EnvoyLogLevel = nil
	agentConfig.ListenerDrainWaitTime = 0

	arguments := buildCommandArgs(agentConfig)

	assert.Equal(t, 1, len(arguments))
	assert.ElementsMatch(t, []string{agentConfig.CommandPath}, arguments)
}

func TestStartCommand(t *testing.T) {
	var agentConfig config.AgentConfig

	agentConfig.SetDefaults()
	agentConfig.EnvoyConfigPath = nil
	agentConfig.EnvoyLogLevel = nil
	agentConfig.CommandPath, _ = exec.LookPath("uname")
	agentConfig.CommandArgs = []string{"-a"}

	logging.SetupLogger(&agentConfig)
	args := buildCommandArgs(agentConfig)

	pid, err := startCommand(agentConfig, args)
	assert.NotEqual(t, pid, -1)
	assert.Nil(t, err)
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
	agentConfig.EnvoyConfigPath = nil
	agentConfig.EnvoyLogLevel = nil
	agentConfig.ListenerDrainWaitTime = 0
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
	agentConfig.EnvoyConfigPath = nil
	agentConfig.EnvoyLogLevel = nil
	agentConfig.ListenerDrainWaitTime = 0
	agentConfig.EnvoyRestartCount = 2
	agentConfig.CommandPath, _ = exec.LookPath("sleep")
	agentConfig.CommandArgs = []string{"3"}

	logging.SetupLogger(&agentConfig)

	var messageSources messagesources.MessageSources
	messageSources.SetupChannels()

	start := time.Now()

	go keepCommandAlive(agentConfig, &messageSources)

	var processDeadCount int = 0
	var pid []int = make([]int, 0)

	for {
		loopElapsed := time.Since(start).Seconds()
		if loopElapsed > executionTimeout {
			log.Debugf("Exiting loop because we spent more than %f seconds looping\n", executionTimeout)
			assert.Fail(t, "Exceeded maximum execution time.")
		}

		// Allow the keepCommandAlive loop to execute at least once and update the status
		time.Sleep(3 * agentConfig.PidPollInterval)

		// Get the pid and store it for validation later
		var found bool = false
		pidVal := messageSources.GetPid()
		if pidVal > 0 {
			// There's no contains function!?
			for _, val := range pid {
				if pidVal == val {
					found = true
				}
			}

			if !found {
				pid = append(pid, pidVal)
			}
		}

		if !messageSources.GetProcessStatus() {
			processDeadCount++
			if processDeadCount == agentConfig.EnvoyRestartCount {
				log.Debugf("Exiting loop because process exited [restarts=%d]\n", processDeadCount)
				break
			}
		}
	}

	elapsed := time.Since(start).Seconds()

	// Verify that we have "restartCount + 1 (initial process id)" number of pids
	assert.Equal(t, agentConfig.EnvoyRestartCount+1, len(pid))

	// Verify that the process state channel is false since the forked process is no longer active.
	assert.False(t, messageSources.GetProcessStatus())

	// Validate that we ran 3 instances of "sleep 3", which should take more than 8 seconds
	assert.Less(t, minimumExecutionTime, elapsed)

	// Validate that we did not run for longer than 10 seconds.
	assert.GreaterOrEqual(t, executionTimeout, elapsed)
}

func setupEnvoyAdminServer(agentConfig config.AgentConfig) *httptest.Server {
	// Setup Envoy admin server
	var drainResponse string = "OK\n"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(res http.ResponseWriter, r *http.Request) {
		res.WriteHeader(200)
		res.Write([]byte(drainResponse))
	}))

	// Create a new listener to listen om Envoy Admin Port
	listener, _ := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", agentConfig.EnvoyServerAdminPort))

	// Close the httptest listener as it listens on port 80 by default
	srv.Listener.Close()

	// Attach the new listener to the httptest server
	srv.Listener = listener
	srv.Start()
	return srv
}

func TestDrainListenerEndpoint(t *testing.T) {
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	// Setup Envoy admin server
	srv := setupEnvoyAdminServer(agentConfig)
	defer srv.Close()

	res, err := http.Post(fmt.Sprintf("%s/%s", srv.URL, agentConfig.EnvoyListenerDrainUrl), "", nil)
	defer res.Body.Close()
	responseData, _ := ioutil.ReadAll(res.Body)

	assert.Nil(t, err)
	assert.NotNil(t, res)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "OK\n", string(responseData))
}

func TestDrainEnvoyListeners(t *testing.T) {
	// Drain for 5 secs
	drainTime := 5 * time.Second
	executionTime := 6 * time.Second
	os.Setenv("LISTENER_DRAIN_WAIT_TIME_S", strconv.Itoa(int(drainTime/time.Second)))
	defer os.Unsetenv("LISTENER_DRAIN_WAIT_TIME_S")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()

	// Setup Envoy admin server
	srv := setupEnvoyAdminServer(agentConfig)
	defer srv.Close()

	// Call listener drain
	start := time.Now()
	drainEnvoyListeners(agentConfig)
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
	os.Setenv("APPNET_ENVOY_LOG_NAME", "agent_log_file_test.log")

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
	agentConfig.EnvoyConfigPath = nil
	agentConfig.EnvoyLogLevel = nil
	agentConfig.ListenerDrainWaitTime = 0
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

func TestLogRotation(t *testing.T) {

	var agentConfig config.AgentConfig

	// Set environment variables redirecting logging to a file on disk
	os.Setenv("APPNET_ENVOY_LOG_DESTINATION", getTmpDir())
	os.Setenv("APPNET_ENVOY_LOG_NAME", "agent_log_file_test.log")

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
	agentConfig.EnvoyConfigPath = nil
	agentConfig.EnvoyLogLevel = nil
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
