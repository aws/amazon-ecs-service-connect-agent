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

package listenerinfo

import (
	"encoding/json"

	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/env"

	log "github.com/sirupsen/logrus"
)

const (
	listenerPortMappingEnvVar = "APPNET_LISTENER_PORT_MAPPING"
	metadataNamespace         = "aws.ecs.serviceconnect.ListenerPortMapping"
)

// BuildMetadata generates a map containing the
// mapping of listener name to listener port number
func BuildMetadata() (map[string]interface{}, error) {
	var listenerPortMapping = env.Or(listenerPortMappingEnvVar, "")
	if listenerPortMapping == "" {
		metadata := map[string]interface{}{}
		return metadata, nil
	}

	var mapping map[string]interface{}

	if err := json.Unmarshal([]byte(listenerPortMapping), &mapping); err != nil {
		log.Errorf("Failed to parse listener port mapping info from env APPNET_LISTENER_PORT_MAPPING: %v", err)
		return nil, err
	}
	log.WithFields(log.Fields{
		metadataNamespace: mapping,
	}).Debug("Generated listenerPortMapping")

	metadata := map[string]interface{}{
		metadataNamespace: mapping,
	}
	return metadata, nil
}
