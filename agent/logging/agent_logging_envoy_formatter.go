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
	"strings"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"

	log "github.com/sirupsen/logrus"
)

// Generic Log Formatter to match Envoy default log Format
type AgentEnvoyLogFormatter struct {
	currentPid int
}

func (f *AgentEnvoyLogFormatter) Format(entry *log.Entry) ([]byte, error) {
	// Format the message to the glog format
	// Reference https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/application_logging.htm
	// '%L%m%d %T.%e %t envoy] [%t][%n]%v' produces
	// [2021-10-20 16:25:59.915][72][debug][pool] [source/common/conn_pool/conn_pool_base.cc:175] [C4] creating stream
	var output string

	// Date and Time
	y, m, d := entry.Time.UTC().Date()
	output += fmt.Sprintf("[%04d-%02d-%02d %02d:%02d:%02d.%03d]",
		y, m, d,
		entry.Time.UTC().Hour(),
		entry.Time.UTC().Minute(),
		entry.Time.UTC().Second(),
		entry.Time.UTC().Nanosecond()/int(time.Millisecond),
	)

	// Process ID
	output += fmt.Sprintf("[%d]", f.currentPid)

	// Log Level
	output += fmt.Sprintf("[%s] [%s] ", strings.ToLower(entry.Level.String()), config.AGENT_LOG_IDENTIFIER)

	// Log Message
	output += entry.Message

	// Map seems to be empty, however append the entries to the end of the log message
	var keyValuePairs string
	if len(entry.Data) > 0 {
		for k, v := range entry.Data {
			if keyValuePairs != "" {
				keyValuePairs += ","
			}
			keyValuePairs += fmt.Sprintf("Key: %s: Value %v\n", k, v)
		}

		if keyValuePairs != "" {
			output += fmt.Sprintf("[%s]", keyValuePairs)
		}
	}

	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	output += "\n"
	b.WriteString(output)

	return b.Bytes(), nil
}
func NewAgentLogFormatter() *AgentEnvoyLogFormatter {
	// Set the pid once on instantiation since the agent pid remains static
	formatter := &AgentEnvoyLogFormatter{
		currentPid: os.Getpid(),
	}

	return formatter
}
