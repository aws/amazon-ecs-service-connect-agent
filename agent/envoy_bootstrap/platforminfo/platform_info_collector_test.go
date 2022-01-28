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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setup() {
	os.Clearenv()
}

func TestBuildMetadataUndefinedEnvVar(t *testing.T) {
	setup()
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	assert.Equal(t, 0, len(*md))
}

func TestBuildK8sPlatformMapNotEnoughInfo(t *testing.T) {
	setup()
	os.Setenv("APPMESH_PLATFORM_K8S_VERSION", "v1.2.1")
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	assert.Equal(t, 0, len(*md))
}

func TestBuildK8sPlatformMap(t *testing.T) {
	setup()
	os.Setenv("APPMESH_PLATFORM_K8S_VERSION", "v1.21.2-eks-0389ca3")
	os.Setenv("APPMESH_PLATFORM_K8S_POD_UID", "f906a249-ab9d-4180-9afa-4075e2058ac7")
	os.Setenv("APPMESH_PLATFORM_APP_MESH_CONTROLLER_VERSION", "v1.4.1")
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)

	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	k8sPlatformMap := platformMap["k8sPlatformInfo"].(map[string]interface{})
	assert.NotNil(t, k8sPlatformMap)
	assert.Equal(t, 3, len(k8sPlatformMap))
	assert.NotNil(t, k8sPlatformMap["k8sVersion"])
	assert.Equal(t, "v1.21.2-eks-0389ca3", k8sPlatformMap["k8sVersion"])
	assert.NotNil(t, k8sPlatformMap["podUid"])
	assert.Equal(t, "f906a249-ab9d-4180-9afa-4075e2058ac7", k8sPlatformMap["podUid"])
	assert.NotNil(t, k8sPlatformMap["appMeshControllerVersion"])
	assert.Equal(t, "v1.4.1", k8sPlatformMap["appMeshControllerVersion"])
}

func setupMetadataServer() *httptest.Server {
	containerMetadataResponse := `{ "Cluster": "TestCluster", "TaskARN": "TestTask" }`
	return httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, r *http.Request) {
		res.WriteHeader(200)
		res.Write([]byte(containerMetadataResponse))
	}))
}

func TestGetEcsContainerMetadata(t *testing.T) {
	setup()
	srv := setupMetadataServer()
	defer srv.Close()

	ecsMetadata := make(map[string]interface{})
	getEcsContainerMetadata(srv.URL, ecsMetadata)

	assert.NotNil(t, ecsMetadata)
	assert.Equal(t, 2, len(ecsMetadata))
	assert.Equal(t, "TestCluster", ecsMetadata["ecsClusterArn"])
	assert.Equal(t, "TestTask", ecsMetadata["ecsTaskArn"])
}

func TestBuildEcsLaunchType(t *testing.T) {
	setup()
	os.Setenv("AWS_EXECUTION_ENV", "AWS_ECS_FARGATE")
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)

	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	ecsPlatformMap := platformMap["ecsPlatformInfo"].(map[string]interface{})
	assert.NotNil(t, ecsPlatformMap)
	assert.Equal(t, 1, len(ecsPlatformMap))
	assert.NotNil(t, ecsPlatformMap["ecsLaunchType"])
	assert.Equal(t, "AWS_ECS_FARGATE", ecsPlatformMap["ecsLaunchType"])
}

func TestBuildEcsPlatformMap(t *testing.T) {
	setup()
	srv := setupMetadataServer()
	defer srv.Close()

	os.Setenv("AWS_EXECUTION_ENV", "AWS_ECS_FARGATE")
	os.Setenv("ECS_CONTAINER_METADATA_URI", srv.URL)

	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)

	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	ecsPlatformMap := platformMap["ecsPlatformInfo"].(map[string]interface{})
	assert.NotNil(t, ecsPlatformMap)
	assert.Equal(t, 3, len(ecsPlatformMap))
	assert.NotNil(t, ecsPlatformMap["ecsLaunchType"])
	assert.Equal(t, "AWS_ECS_FARGATE", ecsPlatformMap["ecsLaunchType"])
	assert.NotNil(t, ecsPlatformMap["ecsClusterArn"])
	assert.Equal(t, "TestCluster", ecsPlatformMap["ecsClusterArn"])
	assert.NotNil(t, ecsPlatformMap["ecsTaskArn"])
	assert.Equal(t, "TestTask", ecsPlatformMap["ecsTaskArn"])
}
