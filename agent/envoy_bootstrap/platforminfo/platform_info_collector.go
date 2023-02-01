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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/aws/aws-app-mesh-agent/agent/client"
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
	ecsExecutionEnvVar            = "AWS_EXECUTION_ENV"
	ecsContainerMetadataUriEnv    = "ECS_CONTAINER_METADATA_URI"
	ecsContainerMetadataUriV4Env  = "ECS_CONTAINER_METADATA_URI_V4"
	ecsContainerMetadataTaskPath  = "/task"
	ecsPlatformInfoKey            = "ecsPlatformInfo"
	ecsLaunchTypeKey              = "ecsLaunchType"
	ecsClusterArnKey              = "ecsClusterArn"
	ecsTaskArnKey                 = "ecsTaskArn"
	ecsEnvoyContainerCpuLimit     = "CPU"
	ecsEnvoyContainerMemoryLimit  = "Memory"
	ecsContainerInstanceArnEnvVar = "ECS_CONTAINER_INSTANCE_ARN"
	ecsContainerInstanceArnKey    = "ecsContainerInstanceArn"

	// Platform independent information
	ec2MetadataUriEnvForTesting = "EC2_METADATA_HOST_ONLY_FOR_TESTING"
	ec2MetadataHost             = "http://169.254.169.254"
	azQuery                     = "placement/availability-zone"
	azIDQuery                   = "placement/availability-zone-id"
	AvailabilityZoneKey         = "AvailabilityZone"
	AvailabilityZoneIDKey       = "AvailabilityZoneID"
	supportedIPFamiliesKey      = "supportedIPFamilies"
	ec2MetadataTokenResource    = "/latest/api/token"
	ec2ImdsTokenHeader          = "X-aws-ec2-metadata-token"
	ec2ImdsTokenTtlHeader       = "X-aws-ec2-metadata-token-ttl-seconds"

	// System Information
	systemInfoKey       = "systemInfo"
	sysPlatformKey      = "systemPlatform"
	sysKernelVersionKey = "systemKernelVersion"
)

func buildMetadataForK8sPlatform(mapping map[string]interface{}) {
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

		// Since IMDS is not accessible from inside ECS, making below 2 calls only on EKS platform.
		// Fetch AZ from EC2 instance metadata if possible.
		if availabilityZone, err := getEc2InstanceMetadata(azQuery); err != nil {
			log.Warnf("Couldn't determine the AZ due to: %v", err)
		} else if availabilityZone != "" {
			mapping[AvailabilityZoneKey] = availabilityZone
		}
		// Fetch AZ ID info as AZ can map differently for each account but AZ IDs are the same for
		// every account https://docs.aws.amazon.com/ram/latest/userguide/working-with-az-ids.html
		if availabilityZoneID, err := getEc2InstanceMetadata(azIDQuery); err != nil {
			// Just log info if we can't get this information
			log.Warnf("Couldn't determine the AZ ID due to: %v", err)
		} else if availabilityZoneID != "" {
			mapping[AvailabilityZoneIDKey] = availabilityZoneID
		}
	}
}

func buildMetadataForEcsPlatform(mapping map[string]interface{}) {
	// ECS platform information

	// Networks info: supportedIPFamilies, it's not an ECS only info, for others we may also need to set this
	supportedIPFamilies := ""

	ecsLaunchType := env.Get(ecsExecutionEnvVar)
	if ecsLaunchType != "" {
		ecsMetadata := map[string]interface{}{
			ecsLaunchTypeKey: ecsLaunchType,
		}

		ecsContainerInstanceArn := env.Get(ecsContainerInstanceArnEnvVar)
		if ecsContainerInstanceArn != "" {
			ecsMetadata[ecsContainerInstanceArnKey] = ecsContainerInstanceArn
		}

		// Look for V4 URI first and fallback on V3 URI
		ecsContainerMetadataUri := env.Or(ecsContainerMetadataUriV4Env, env.Get(ecsContainerMetadataUriEnv))
		// Get ECS container metadata
		if ecsContainerMetadataUri != "" {
			getEcsContainerMetadata(ecsContainerMetadataUri+ecsContainerMetadataTaskPath, ecsMetadata)
			getEcsEnvoyContainerMetadata(ecsContainerMetadataUri, ecsMetadata)
			supportedIPFamilies = getEcsContainerSupportedIPFamilies(ecsContainerMetadataUri + ecsContainerMetadataTaskPath)
		}
		// The AZ info is available from ECS container metadata itself
		if availabilityZone, exists := ecsMetadata[AvailabilityZoneKey]; exists {
			mapping[AvailabilityZoneKey] = availabilityZone
			delete(ecsMetadata, AvailabilityZoneKey)
		}

		// Build SupportedIPFamilies info in platform
		if supportedIPFamilies != "" {
			mapping[supportedIPFamiliesKey] = supportedIPFamilies
		}
		mapping[ecsPlatformInfoKey] = ecsMetadata
	}
}

func buildMetadataFromSystemInfo(mapping map[string]interface{}) {
	// System information
	systemInfo := make(map[string]interface{})
	if platform, err := runCommand("uname", "-p"); err != nil {
		log.Errorf("Unable to get system platform info: %v", err)
	} else {
		systemInfo[sysPlatformKey] = platform
	}
	if kernelVersion, err := runCommand("uname", "-r"); err != nil {
		log.Errorf("Unable to get system kernel version: %v", err)
	} else {
		systemInfo[sysKernelVersionKey] = kernelVersion
	}

	if len(systemInfo) > 0 {
		mapping[systemInfoKey] = systemInfo
	}
}

func BuildMetadata() (*map[string]interface{}, error) {
	md := make(map[string]interface{})
	mapping := make(map[string]interface{})

	buildMetadataForK8sPlatform(mapping)
	buildMetadataForEcsPlatform(mapping)
	buildMetadataFromSystemInfo(mapping)

	if len(mapping) != 0 {
		md[metadataNamespace] = mapping
	}

	return &md, nil
}

func getEcsContainerMetadata(uri string, ecsMetadata map[string]interface{}) {
	metadataMap, err := getEcsMetadata(uri)
	if err != nil {
		log.Warnf("Failed generating ECS platform info from ECS metadata: %v", err)
		return
	}

	// For reference on all the information that is returned from the task metadata endpoint, see
	// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html
	// Here we only pick the ones that are needed.
	if ecsClusterArn := metadataMap["Cluster"]; ecsClusterArn != "" {
		ecsMetadata[ecsClusterArnKey] = ecsClusterArn
	}
	if ecsTaskArn := metadataMap["TaskARN"]; ecsTaskArn != "" {
		ecsMetadata[ecsTaskArnKey] = ecsTaskArn
	}
	if availabilityZone := metadataMap["AvailabilityZone"]; availabilityZone != "" {
		ecsMetadata[AvailabilityZoneKey] = availabilityZone
	}

}

func getEcsEnvoyContainerMetadata(uri string, ecsMetadata map[string]interface{}) {

	response, err := http.Get(uri)
	if err != nil {
		log.Warnf("Unable to fetch ECS envoy container metadata from %s: %v", uri, err)
		return
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Warnf("Unable to read ECS envoy container metadata: %v", err)
		return
	}

	var metadataMap map[string]interface{}
	err = json.Unmarshal(responseBody, &metadataMap)
	if err != nil {
		log.Warnf("Unable to parse ECS envoy container metadata: %v", err)
		return
	}

	// For reference on all the information that is returned from the task metadata endpoint, see
	// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html
	// Here we only pick the ones that are needed.
	if CPULimit := fmt.Sprintf("%v", metadataMap["Limits"].(map[string]interface{})["CPU"]); CPULimit != "" {
		ecsMetadata[ecsEnvoyContainerCpuLimit] = CPULimit
	}
	if MemoryLimit := fmt.Sprintf("%v", metadataMap["Limits"].(map[string]interface{})["Memory"]); MemoryLimit != "" {
		ecsMetadata[ecsEnvoyContainerMemoryLimit] = MemoryLimit
	}
}

func getEcsMetadata(uri string) (map[string]interface{}, error) {
	var metadataMap map[string]interface{}
	response, err := http.Get(uri)
	if err != nil {
		log.Warnf("Unable to fetch ECS container metadata from %s: %v", uri, err)
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Warnf("Unable to read ECS container metadata: %v", err)
		return nil, err
	}

	err = json.Unmarshal(responseBody, &metadataMap)
	if err != nil {
		log.Warnf("Unable to parse ECS container metadata: %s, %v", responseBody, err)
		return nil, err
	}
	return metadataMap, nil
}

func getEcsContainerSupportedIPFamilies(uri string) string {
	metadataMap, err := getEcsMetadata(uri)
	if err != nil {
		log.Warnf("Failed generating SupportedIPFamilies info from ECS metadata: %v", err)
		return ""
	}
	containers := metadataMap["Containers"]
	if containers == nil || len(containers.([]interface{})) == 0 {
		log.Warnf("Containers info not found in ECS metadata: %v", metadataMap)
		return ""
	}
	// all containers share the same networks
	containerInfo := containers.([]interface{})[0]
	networks := containerInfo.(map[string]interface{})["Networks"]
	if networks == nil || len(networks.([]interface{})) == 0 {
		log.Warnf("Networks info not found in container info in ECS metadata: %v", containerInfo)
		return ""
	}

	hasIPv4Addresses := false
	hasIPv6Addresses := false
	networksArray := networks.([]interface{})
	for i := 0; i < len(networksArray); i++ {
		if networksArray[i].(map[string]interface{})["IPv4Addresses"] != nil {
			hasIPv4Addresses = true
		}
		if networksArray[i].(map[string]interface{})["IPv6Addresses"] != nil {
			hasIPv6Addresses = true
		}
	}
	if hasIPv4Addresses && hasIPv6Addresses {
		return "ALL"
	}
	if hasIPv4Addresses {
		return "IPv4_ONLY"
	}
	if hasIPv6Addresses {
		return "IPv6_ONLY"
	}
	log.Warnf("Neither IPv4 or IPv6 addresses are found in ECS metadata Networks")
	return ""
}

func getEc2InstanceMetadata(query string) (string, error) {
	httpClient := client.CreateDefaultHttpClient()
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
	// EC2 Instance Metadata url to get the token: http://169.254.169.254/latest/api/token
	token := ""
	tokenRequestUrl := env.Or(ec2MetadataUriEnvForTesting, ec2MetadataHost) + ec2MetadataTokenResource
	tokenRequest, err := client.CreateStandardAgentHttpRequest(http.MethodPut, tokenRequestUrl, nil)
	if err != nil {
		log.Debugf("unable to create http request: %v. request url: %s", err, tokenRequestUrl)
	} else {
		// Setting token expiry time to just 2 seconds instead of default 21600 seconds
		tokenRequest.Header.Add(ec2ImdsTokenTtlHeader, "2")
		tokenResponse, err := httpClient.Do(tokenRequest)
		if err != nil || tokenResponse == nil || tokenResponse.Body == nil {
			log.Debugf("unable to make a put call to EC2 Instance Metadata, request url: %s, error: %s "+
				"to fetch the instance metadata token. Falling back to insure way of calling EC2 Instance Metadata.",
				tokenRequestUrl, err)
		} else {
			defer tokenResponse.Body.Close()
			if tokenResponse.StatusCode != 200 {
				log.Debugf("unable to make a put call to EC2 Instance Metadata, request url: %s, code: %s "+
					"to fetch the instance metadata token. Falling back to insure way of calling EC2 Instance Metadata.",
					tokenRequestUrl, strconv.Itoa(tokenResponse.StatusCode))
			} else if responseBody, err := ioutil.ReadAll(tokenResponse.Body); err != nil {
				log.Debugf("unable to make a put call to EC2 Instance Metadata, request url: %s, error: %s "+
					"to fetch the instance metadata token. Falling back to insure way of calling EC2 Instance Metadata.",
					tokenRequestUrl, err)
			} else {
				log.Debugf("Successfully obtained token to make secure call to EC2 Instance Metadata")
				token = string(responseBody)
			}
		}
	}
	// EC2 Instance Metadata url: http://169.254.169.254/latest/meta-data/
	requestUrl := env.Or(ec2MetadataUriEnvForTesting, ec2MetadataHost) + "/latest/meta-data/" + query
	imdsRequest, err := client.CreateStandardAgentHttpRequest(http.MethodGet, requestUrl, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create http request: %v. request url: %s", err, requestUrl)
	}
	if token != "" {
		imdsRequest.Header.Add(ec2ImdsTokenHeader, token)
	}
	response, err := httpClient.Do(imdsRequest)
	if err != nil {
		return "", fmt.Errorf("unable to query from IMDSv1, request url: %s, error: %s", requestUrl, err)
	}
	defer response.Body.Close()
	if responseBody, err := ioutil.ReadAll(response.Body); err != nil {
		return "", fmt.Errorf("unable to read EC2 instance metadata for query %s: %v", query, err)
	} else {
		return string(responseBody), nil
	}
}

func runCommand(name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &out
	err := cmd.Run()
	return strings.TrimSuffix(out.String(), "\n"), err
}
