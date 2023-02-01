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

package applicationinfo

import (
	"encoding/json"

	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/env"

	log "github.com/sirupsen/logrus"
)

const (
	containerIPMappingEnvVar = "APPNET_CONTAINER_IP_MAPPING"
	metadataNamespace        = "aws.ecs.serviceconnect.ClusterIPMapping"
)

// BuildMetadata generates a map containing the
// mapping of container name to container ip address
func BuildMetadata() (map[string]interface{}, error) {
	var containerIPMapping = env.Or(containerIPMappingEnvVar, "")
	if containerIPMapping == "" {
		metadata := map[string]interface{}{}
		return metadata, nil
	}

	var mapping map[string]interface{}

	if err := json.Unmarshal([]byte(containerIPMapping), &mapping); err != nil {
		log.Errorf("Failed to parse container ip mapping info from env APPNET_CONTAINER_IP_MAPPING: %v", err)
		return nil, err
	}
	log.WithFields(log.Fields{
		metadataNamespace: mapping,
	}).Debug("Generated containerIPMapping")

	metadata := map[string]interface{}{
		metadataNamespace: mapping,
	}
	return metadata, nil
}
