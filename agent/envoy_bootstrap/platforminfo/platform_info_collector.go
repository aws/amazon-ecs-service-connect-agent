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

package platforminfo

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/env"

	log "github.com/sirupsen/logrus"
)

const (
	metadataNamespace = "aws.appmesh.platformInfo"

	// K8s Info
	k8sVersionEnvVar               = "APPMESH_PLATFORM_K8S_VERSION"
	podUidEnvVar                   = "APPMESH_PLATFORM_K8S_POD_UID"
	appMeshControllerVersionEnvVar = "APPMESH_PLATFORM_APP_MESH_CONTROLLER_VERSION"
	k8sPlatformInfoKey             = "k8sPlatformInfo"
	k8sVersionKey                  = "k8sVersion"
	podUidKey                      = "podUid"
	appMeshControllerVersionKey    = "appMeshControllerVersion"

	// ECS Info
	ecsExecutionEnvVar           = "AWS_EXECUTION_ENV"
	ecsContainerMetadataUriEnv   = "ECS_CONTAINER_METADATA_URI"
	ecsContainerMetadataUriV4Env = "ECS_CONTAINER_METADATA_URI_V4"
	ecsContainerMetadataTaskPath = "/task"
	ecsPlatformInfoKey           = "ecsPlatformInfo"
	ecsLaunchTypeKey             = "ecsLaunchType"
	ecsClusterArnKey             = "ecsClusterArn"
	ecsTaskArnKey                = "ecsTaskArn"
)

func BuildMetadata() (*map[string]interface{}, error) {
	md := make(map[string]interface{})
	mapping := make(map[string]interface{})

	// K8s platform information
	k8sVersion := env.Get(k8sVersionEnvVar)
	podUid := env.Get(podUidEnvVar)
	appMeshControllerVersion := env.Get(appMeshControllerVersionEnvVar)

	// TODO: Add EKS cluster info when available
	if k8sVersion != "" && podUid != "" && appMeshControllerVersion != "" {
		mapping[k8sPlatformInfoKey] = map[string]interface{}{
			k8sVersionKey:               k8sVersion,
			podUidKey:                   podUid,
			appMeshControllerVersionKey: appMeshControllerVersion,
		}
	}

	// ECS platform information
	ecsLaunchType := env.Get(ecsExecutionEnvVar)
	if ecsLaunchType != "" {
		ecsMetadata := map[string]interface{}{
			ecsLaunchTypeKey: ecsLaunchType,
		}

		// Look for V4 URI first and fallback on V3 URI
		ecsContainerMetadataUri := env.Or(ecsContainerMetadataUriV4Env, env.Get(ecsContainerMetadataUriEnv))
		// Get ECS container metadata
		if ecsContainerMetadataUri != "" {
			getEcsContainerMetadata(ecsContainerMetadataUri+ecsContainerMetadataTaskPath, ecsMetadata)
		}
		mapping[ecsPlatformInfoKey] = ecsMetadata
	}

	if len(mapping) != 0 {
		md[metadataNamespace] = mapping
	}

	return &md, nil
}

func getEcsContainerMetadata(uri string, ecsMetadata map[string]interface{}) {
	response, err := http.Get(uri)
	if err != nil {
		log.Warnf("Unable to fetch ECS container metadata from %s: %v", uri, err)
		return
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Warnf("Unable to read ECS container metadata: %v", err)
		return
	}

	var metadataMap map[string]interface{}
	err = json.Unmarshal(responseBody, &metadataMap)
	if err != nil {
		log.Warnf("Unable to parse ECS container metadata: %v", err)
		return
	}

	if ecsClusterArn := metadataMap["Cluster"]; ecsClusterArn != "" {
		ecsMetadata[ecsClusterArnKey] = ecsClusterArn
	}
	if ecsTaskArn := metadataMap["TaskARN"]; ecsTaskArn != "" {
		ecsMetadata[ecsTaskArnKey] = ecsTaskArn
	}
}
