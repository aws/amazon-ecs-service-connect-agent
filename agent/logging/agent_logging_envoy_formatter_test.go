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
	"os"
	"testing"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLogFormat(t *testing.T) {

	var agentConfig config.AgentConfig
	var expected string
	var actual string

	agentConfig.SetDefaults()

	formatter := NewAgentLogFormatter()
	entry := &log.Entry{
		Level:   log.DebugLevel,
		Time:    time.Time{},
		Message: "sit like a seed under covers of earth and just be",
	}

	output, err := formatter.Format(entry)
	assert.Nil(t, err)

	expected = fmt.Sprintf("[0001-01-01 00:00:00.000][%d][debug] [AppNet Agent] sit like a seed under covers of earth and just be\n", os.Getpid())
	actual = string(output)
	assert.Equal(t, expected, actual)
}

func TestLogFormatUsingBuffer(t *testing.T) {

	var agentConfig config.AgentConfig
	var expected string
	var actual string
	var customBuffer bytes.Buffer

	agentConfig.SetDefaults()

	formatter := NewAgentLogFormatter()
	entry := &log.Entry{
		Level:   log.DebugLevel,
		Time:    time.Time{},
		Buffer:  &customBuffer,
		Message: "sit like the sun, by a star in the sky and just be",
	}

	_, err := formatter.Format(entry)
	assert.Nil(t, err)

	expected = fmt.Sprintf("[0001-01-01 00:00:00.000][%d][debug] [AppNet Agent] sit like the sun, by a star in the sky and just be\n", os.Getpid())
	actual = customBuffer.String()
	assert.Equal(t, expected, actual)
}
