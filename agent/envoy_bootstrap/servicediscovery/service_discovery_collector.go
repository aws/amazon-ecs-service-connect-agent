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

package servicediscovery

import (
	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/env"
)

const (
	metadataNamespace = "aws.ecs.serviceconnect.ServiceDiscovery"

	namespaceNameEnvVar = "NAMESPACE_NAME"
	namespaceArnEnvVar  = "NAMESPACE_ARN"

	namespaceNameKey = "NamespaceName"
	namespaceArnKey  = "NamespaceArn"
)

// BuildMetadata generates a metadata map containing the Cloud Map service
// discovery namespace info (name and ARN) read from environment variables
// set by RMS on the SC agent container.
//
// When neither env var is set, the returned map is empty and the
// aws.ecs.serviceconnect.ServiceDiscovery key will not appear in the final
// Envoy node metadata.
func BuildMetadata() (map[string]interface{}, error) {
	mapping := make(map[string]interface{})

	if v := env.Get(namespaceNameEnvVar); v != "" {
		mapping[namespaceNameKey] = v
	}
	if v := env.Get(namespaceArnEnvVar); v != "" {
		mapping[namespaceArnKey] = v
	}

	metadata := map[string]interface{}{}
	if len(mapping) > 0 {
		metadata[metadataNamespace] = mapping
	}
	return metadata, nil
}
