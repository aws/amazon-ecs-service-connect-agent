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
	"bufio"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/aws/aws-app-mesh-agent/agent/config"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLoggingToStderr(t *testing.T) {
	var agentConfig config.AgentConfig

	// Setting stderr to nil here since closing and reopening does not work as expected
	// and affects other tests.  If running this single test, calling close on the
	// File will have the same effect.
	stderErrFilep := os.Stderr
	os.Stderr = nil

	agentConfig.SetDefaults()

	SetupLogger(&agentConfig)
	log.SetLevel(log.DebugLevel)

	log.Error("Test message that should *NEVER* display since stderr is unavailable")
	log.Info("Sadly we have to rely on visual verification that we never see these messages")
	log.Warn("This confirms that the custom writer we provide to the logger still honors")
	log.Debug("the default output sink of stderr")

	// Restore the stderr File handle
	os.Stderr = stderErrFilep
}

func getTmpDir() string {
	tempDir := os.Getenv("TMPDIR")
	if len(tempDir) == 0 {
		tempDir = "/tmp"
	}
	return tempDir
}

func TestLoggingToFile(t *testing.T) {
	var minFileSize int64 = 250
	var agentConfig config.AgentConfig

	os.Setenv("APPNET_ENVOY_LOG_DESTINATION", getTmpDir())
	os.Setenv("APPNET_ENVOY_LOG_NAME", "agent_log_file_test_TestLoggingToFile.log")

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
	SetupLogger(&agentConfig)

	// Set the log level to debug so we capture the debug log message below
	log.SetLevel(log.DebugLevel)

	log.Info("Test message that should never display on the console")
	log.Error("Fortunately we can check the log file for its presence")
	log.Warn("Once we know it's on disk, we can check the contents")
	log.Debug("Everything we log should be in it")

	// Verify that the log file was created and has data
	fileInfo, err := os.Stat(logPath)
	assert.Nil(t, err)
	assert.Greater(t, fileInfo.Size(), minFileSize)

	fp, err := os.Open(logPath)
	assert.Nil(t, err)
	reader := bufio.NewReader(fp)

	// Read the contents of the log line and verify the 4 log levels exist
	var lineCount int
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}

		if strings.Contains(line, "[info]") ||
			strings.Contains(line, "[error]") ||
			strings.Contains(line, "[warning]") ||
			strings.Contains(line, "[debug]") {
			lineCount++
		}
	}
	assert.GreaterOrEqual(t, lineCount, 4)
}

// Skip this test since it "works" on codebuild.  We are not
// running as a root user, however we can create files in /.
// The log file contains 300+ bytes of data, and we expect this
// not to happen.  Instead of writing a location aware test
// we will turn it off for now.
func TestLoggingToFileFailure(t *testing.T) {
	var agentConfig config.AgentConfig

	codebuild := os.Getenv("CODEBUILD_SRC_DIR")
	if len(codebuild) != 0 {
		return
	}

	// If this test runs as root it will fail. Need to assert uid != 0
	assert.NotEqualValues(t, "0", os.Getenv("UID"))

	// We will not have permissions to write or create files in root
	// so output redirection should fail
	os.Setenv("APPNET_ENVOY_LOG_DESTINATION", "/")
	os.Setenv("APPNET_ENVOY_LOG_NAME", "agent_log_file_test_TestLoggingToFileFailure.log")

	defer os.Unsetenv("APPNET_ENVOY_LOG_DESTINATION")
	defer os.Unsetenv("APPNET_ENVOY_LOG_NAME")

	logPath := path.Join(
		os.Getenv("APPNET_ENVOY_LOG_DESTINATION"),
		os.Getenv("APPNET_ENVOY_LOG_NAME"),
	)

	// Setup the logger based on the config
	agentConfig.SetDefaults()
	SetupLogger(&agentConfig)

	log.Info("Test message that should display on the console")
	log.Error("Unfortunately we can't check the log file for its presence")
	log.Warn("We should not be able to write to root")
	log.Debug("So, these messages show up on stderr")

	// Verify that the log file was not created.
	_, err := os.Stat(logPath)
	assert.NotNil(t, err)
}
