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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setup() {
	os.Clearenv()
}

type ImdsReqRes struct {
	query    string
	method   string
	response string
	header   string
}

func setupEc2MetadataServer(imdsReqResList []ImdsReqRes, sleep time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, r *http.Request) {
		time.Sleep(sleep)
		for _, imdsReqRes := range imdsReqResList {
			if strings.HasSuffix(r.URL.Path, imdsReqRes.query) {
				if strings.ToLower(r.Method) == strings.ToLower(imdsReqRes.method) {
					for headerKey, _ := range r.Header {
						if imdsReqRes.header == "" ||
							strings.ToLower(headerKey) == strings.ToLower(imdsReqRes.header) {
							res.WriteHeader(http.StatusOK)
							res.Write([]byte(imdsReqRes.response))
							return
						}
					}
					res.WriteHeader(http.StatusBadRequest)
					res.Write([]byte("400 - Bad Request"))
					return
				} else {
					res.WriteHeader(http.StatusMethodNotAllowed)
					res.Write([]byte("405 - Method Not Allowed"))
					return
				}
			}
		}
		res.WriteHeader(http.StatusNotFound)
		res.Write([]byte("404 - Not Found"))
	}))
}

func setupEcsMetadataServer() *httptest.Server {
	mux := http.NewServeMux()
	containerEnvoyMetadataResponse := `{"Limits": {
										"CPU": 5,
										"Memory": 0.25}}`
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte(containerEnvoyMetadataResponse))
	})
	containerMetadataResponseIpv4 := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
	"Containers":[{"Name": "internal-ecs-pause", "Networks": [{"NetworkMode": "awsvpc", "IPv4Addresses": ["10.0.106.1"]}]},
	{"Name": "test", "Networks": [{"NetworkMode": "awsvpc", "IPv4Addresses": ["10.0.106.1"]}]}]}`
	mux.HandleFunc("/ecsmetadata/ipv4/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseIpv4))
	})

	containerMetadataResponseIpv6 := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
	"Containers":[{"Name": "internal-ecs-pause", "Networks": [{"NetworkMode": "awsvpc", "IPv6Addresses": ["2600:1f13:604:c601:e861:7b20:91fe:881e"]}]},
	{"Name": "test", "Networks": [{"NetworkMode": "awsvpc", "IPv6Addresses": ["2600:1f13:604:c601:e861:7b20:91fe:881e"]}]}]}`
	mux.HandleFunc("/ecsmetadata/ipv6/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseIpv6))
	})

	containerMetadataResponseAll := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
	"Containers":[{"Name": "internal-ecs-pause", "Networks": [{"NetworkMode": "awsvpc","IPv4Addresses": ["10.0.106.1"], "IPv6Addresses": ["2600:1f13:604:c601:e861:7b20:91fe:881e"]}]},
    {"Name": "test", "Networks": [{"NetworkMode": "awsvpc","IPv4Addresses": ["10.0.106.1"], "IPv6Addresses": ["2600:1f13:604:c601:e861:7b20:91fe:881e"]}]}]}`
	mux.HandleFunc("/ecsmetadata/all/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseAll))
	})

	containerMetadataResponseNoIpAddresses := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
       	"Containers":[{"Name": "internal-ecs-pause", "Networks": [{"NetworkMode": "awsvpc"}]},
       	{"Name": "test", "Networks": [{"NetworkMode": "awsvpc"}]}]}`
	mux.HandleFunc("/ecsmetadata/NoIp/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseNoIpAddresses))
	})

	containerMetadataResponseNoNetworks := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
       	"Containers":[{"Name": "internal-ecs-pause"},
       	{"Name": "test"}]}`
	mux.HandleFunc("/ecsmetadata/NoNetworks/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseNoNetworks))
	})

	containerMetadataResponseDefault := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d"}`
	mux.HandleFunc("/ecsmetadata/default/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseDefault))
	})
	srv := httptest.NewServer(mux)
	return srv
}

func setupEcsBridgeModeMetadataServer() *httptest.Server {
	mux := http.NewServeMux()
	containerEnvoyMetadataResponse := `{"Limits": {
										"CPU": 5,
										"Memory": 0.25}}`
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte(containerEnvoyMetadataResponse))
	})

	// Bridge mode with CNI_PAUSE container having IPv4 only
	containerMetadataResponseBridgeIpv4 := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
	"Containers":[
		{"Name": "pause", "Type": "CNI_PAUSE", "Networks": [{"NetworkMode": "bridge", "IPv4Addresses": ["172.17.0.8"]}]},
		{"Name": "nginx-client", "Type": "NORMAL", "Networks": [{"NetworkMode": "container:7d6bba905ead9cbd5b4b0e733e6ba8fef8e655339dc2ea971bb527d0c102c0b2", "IPv4Addresses": [""]}]},
		{"Name": "web-client", "Type": "NORMAL", "Networks": [{"NetworkMode": "container:7d6bba905ead9cbd5b4b0e733e6ba8fef8e655339dc2ea971bb527d0c102c0b2", "IPv4Addresses": [""]}]}
	]}`
	mux.HandleFunc("/ecsmetadata/bridge/ipv4/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseBridgeIpv4))
	})

	// Bridge mode with CNI_PAUSE container having both IPv4 and IPv6
	containerMetadataResponseBridgeDual := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
	"Containers":[
		{"Name": "pause", "Type": "CNI_PAUSE", "Networks": [{"NetworkMode": "bridge", "IPv4Addresses": ["172.17.0.8"], "IPv6Addresses": ["2001:db8:1::242:ac11:8"]}]},
		{"Name": "nginx-client", "Type": "NORMAL", "Networks": [{"NetworkMode": "container:7d6bba905ead9cbd5b4b0e733e6ba8fef8e655339dc2ea971bb527d0c102c0b2", "IPv4Addresses": [""]}]},
		{"Name": "web-client", "Type": "NORMAL", "Networks": [{"NetworkMode": "container:7d6bba905ead9cbd5b4b0e733e6ba8fef8e655339dc2ea971bb527d0c102c0b2", "IPv4Addresses": [""]}]}
	]}`
	mux.HandleFunc("/ecsmetadata/bridge/dual/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseBridgeDual))
	})

	// Test case where first container has invalid network mode, but second container has valid one
	containerMetadataResponseNetworkModeIteration := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
	"Containers":[
		{"Name": "nginx-client", "Type": "NORMAL", "Networks": [{"NetworkMode": "container:26b9f92b669c49893d2c05a8aee10af7bc37207f3a5353f46c17fc747dea353b", "IPv4Addresses": [""]}]},
		{"Name": "pause", "Type": "CNI_PAUSE", "Networks": [{"NetworkMode": "bridge", "IPv4Addresses": ["172.17.0.8"]}]},
		{"Name": "web-client", "Type": "NORMAL", "Networks": [{"NetworkMode": "container:26b9f92b669c49893d2c05a8aee10af7bc37207f3a5353f46c17fc747dea353b", "IPv4Addresses": [""]}]}
	]}`
	mux.HandleFunc("/ecsmetadata/bridge/networkmode-iteration/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseNetworkModeIteration))
	})

	// Test case where a container has multiple networks, with the second network having a valid mode
	containerMetadataResponseMultipleNetworks := `{ "Cluster": "TestCluster", "TaskARN": "TestTask", "AvailabilityZone": "us-west-2d",
	"Containers":[
		{"Name": "multi-network-container", "Type": "NORMAL", "Networks": [
			{"NetworkMode": "container:invalid123", "IPv4Addresses": [""]},
			{"NetworkMode": "awsvpc", "IPv4Addresses": ["10.0.0.5"], "IPv6Addresses": ["2001:db8::5"]}
		]}
	]}`
	mux.HandleFunc("/ecsmetadata/awsvpc/multiple-networks/task", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(containerMetadataResponseMultipleNetworks))
	})

	srv := httptest.NewServer(mux)
	return srv
}

func TestBuildSystemInfoMap(t *testing.T) {
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)

	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	systemInfoMap := platformMap["systemInfo"].(map[string]interface{})
	assert.NotNil(t, systemInfoMap)
	assert.Equal(t, 2, len(systemInfoMap))
	assert.NotNil(t, systemInfoMap["systemPlatform"])
	assert.NotNil(t, systemInfoMap["systemKernelVersion"])
}

func TestBuildMetadataUndefinedEnvVar(t *testing.T) {
	setup()
	// Returning empty response on call to EC2 metadata host
	azQueryImdsReqRes := ImdsReqRes{query: azQuery, method: "GET", response: "", header: ec2ImdsTokenHeader}
	azIDQueryImdsReqRes := ImdsReqRes{query: azIDQuery, method: "GET", response: "", header: ec2ImdsTokenHeader}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "non-empty-token", header: ec2ImdsTokenTtlHeader}
	srv := setupEc2MetadataServer([]ImdsReqRes{azQueryImdsReqRes, azIDQueryImdsReqRes, tokenQueryImdsReqRes}, 0)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	assert.Equal(t, 0, len(*md))
}

func TestBuildK8sPlatformMapNotEnoughInfo(t *testing.T) {
	setup()
	// Returning empty response on call to EC2 metadata host
	azQueryImdsReqRes := ImdsReqRes{query: azQuery, method: "GET", response: "", header: ec2ImdsTokenHeader}
	azIDQueryImdsReqRes := ImdsReqRes{query: azIDQuery, method: "GET", response: "", header: ec2ImdsTokenHeader}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "non-empty-token", header: ec2ImdsTokenTtlHeader}
	srv := setupEc2MetadataServer([]ImdsReqRes{azQueryImdsReqRes, azIDQueryImdsReqRes, tokenQueryImdsReqRes}, 0)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	os.Setenv(k8sVersionEnvVar, "v1.2.1")
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)
	defer os.Unsetenv(k8sVersionEnvVar)
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	assert.Equal(t, 0, len(*md))
}

func TestBuildK8sPlatformMap(t *testing.T) {
	setup()
	azQueryImdsReqRes := ImdsReqRes{query: azQuery, method: "GET", response: "us-west-2d", header: ec2ImdsTokenHeader}
	azIDQueryImdsReqRes := ImdsReqRes{query: azIDQuery, method: "GET", response: "usw2-az2", header: ec2ImdsTokenHeader}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "non-empty-token", header: ec2ImdsTokenTtlHeader}
	srv := setupEc2MetadataServer([]ImdsReqRes{azQueryImdsReqRes, azIDQueryImdsReqRes, tokenQueryImdsReqRes}, 0)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	os.Setenv(k8sVersionEnvVar, "v1.21.2-eks-0389ca3")
	os.Setenv(podUidEnvVar, "f906a249-ab9d-4180-9afa-4075e2058ac7")
	os.Setenv(appMeshControllerVersionEnvVar, "v1.4.1")
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)
	defer os.Unsetenv(k8sVersionEnvVar)
	defer os.Unsetenv(podUidEnvVar)
	defer os.Unsetenv(appMeshControllerVersionEnvVar)

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
	assert.NotNil(t, platformMap["AvailabilityZone"])
	assert.Equal(t, "us-west-2d", platformMap["AvailabilityZone"])
	assert.NotNil(t, platformMap["AvailabilityZoneID"])
	assert.Equal(t, "usw2-az2", platformMap["AvailabilityZoneID"])
}

func TestGetEcsContainerMetadata(t *testing.T) {
	setup()
	srv := setupEcsMetadataServer()
	defer srv.Close()

	ecsMetadata := make(map[string]interface{})
	getEcsContainerMetadata(srv.URL+"/ecsmetadata/default/task", ecsMetadata)
	getEcsEnvoyContainerMetadata(srv.URL, ecsMetadata)
	assert.NotNil(t, ecsMetadata)
	assert.Equal(t, 5, len(ecsMetadata))
	assert.Equal(t, "TestCluster", ecsMetadata["ecsClusterArn"])
	assert.Equal(t, "TestTask", ecsMetadata["ecsTaskArn"])
	assert.Equal(t, "us-west-2d", ecsMetadata["AvailabilityZone"])
	assert.Equal(t, "5", ecsMetadata["CPU"])
	assert.Equal(t, "0.25", ecsMetadata["Memory"])
}

func TestGetAZFromEc2InstanceMetadata(t *testing.T) {
	setup()
	// Don't Exceed the default timeout of 250ms for http call
	// from inside the func `getEc2InstanceMetadata`
	azQueryImdsReqRes := ImdsReqRes{query: azQuery, method: "GET", response: "us-west-2d", header: ec2ImdsTokenHeader}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "non-empty-token", header: ec2ImdsTokenTtlHeader}
	srv := setupEc2MetadataServer([]ImdsReqRes{azQueryImdsReqRes, tokenQueryImdsReqRes}, 200*time.Millisecond)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)

	az, err := getEc2InstanceMetadata(azQuery)

	assert.Nil(t, err)
	assert.NotNil(t, az)
	assert.Equal(t, "us-west-2d", az)
}

func TestGetAZIDFromEc2InstanceMetadata(t *testing.T) {
	setup()
	// Don't Exceed the default timeout of 250ms for http call
	// from inside the func `getEc2InstanceMetadata`
	azIDQueryImdsReqRes := ImdsReqRes{query: azIDQuery, method: "GET", response: "usw2-az2", header: ec2ImdsTokenHeader}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "non-empty-token", header: ec2ImdsTokenTtlHeader}
	srv := setupEc2MetadataServer([]ImdsReqRes{azIDQueryImdsReqRes, tokenQueryImdsReqRes}, 200*time.Millisecond)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)

	azID, err := getEc2InstanceMetadata(azIDQuery)

	assert.Nil(t, err)
	assert.NotNil(t, azID)
	assert.Equal(t, "usw2-az2", azID)
}

func TestEc2InstanceMetadataTimeout(t *testing.T) {
	setup()
	// Exceed the default timeout of 250ms for http call
	// from inside the func `getEc2InstanceMetadata`
	azQueryImdsReqRes := ImdsReqRes{query: azQuery, method: "GET", response: "us-west-2d", header: ""}
	azIDQueryImdsReqRes := ImdsReqRes{query: azIDQuery, method: "GET", response: "usw2-az2", header: ""}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "non-empty-token", header: ec2ImdsTokenTtlHeader}
	srv := setupEc2MetadataServer([]ImdsReqRes{azQueryImdsReqRes, azIDQueryImdsReqRes, tokenQueryImdsReqRes}, 251*time.Millisecond)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)

	az, err := getEc2InstanceMetadata(azQuery)
	assert.NotNil(t, err)
	assert.Empty(t, az)

	azID, err := getEc2InstanceMetadata(azIDQuery)
	assert.NotNil(t, err)
	assert.Empty(t, azID)
}

func TestEc2InstanceMetadataUnsecure(t *testing.T) {
	setup()
	// Request for token gives empty response, and we would still fall back to IMDSv1
	azQueryImdsReqRes := ImdsReqRes{query: azQuery, method: "GET", response: "us-west-2d", header: ""}
	azIDQueryImdsReqRes := ImdsReqRes{query: azIDQuery, method: "GET", response: "usw2-az2", header: ""}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "", header: ec2ImdsTokenTtlHeader}
	srv := setupEc2MetadataServer([]ImdsReqRes{azQueryImdsReqRes, azIDQueryImdsReqRes, tokenQueryImdsReqRes}, 200*time.Millisecond)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)

	az, err := getEc2InstanceMetadata(azQuery)
	assert.Nil(t, err)
	assert.NotNil(t, az)
	assert.Equal(t, "us-west-2d", az)

	azID, err := getEc2InstanceMetadata(azIDQuery)
	assert.Nil(t, err)
	assert.NotNil(t, azID)
	assert.Equal(t, "usw2-az2", azID)
}

func TestEc2InstanceMetadataTokenRequestFails(t *testing.T) {
	setup()
	// Request for token fails, and we would still fall back to IMDSv1
	azQueryImdsReqRes := ImdsReqRes{query: azQuery, method: "GET", response: "us-west-2d", header: ""}
	azIDQueryImdsReqRes := ImdsReqRes{query: azIDQuery, method: "GET", response: "usw2-az2", header: ""}
	tokenQueryImdsReqRes := ImdsReqRes{query: "token", method: "PUT", response: "", header: ""}
	srv := setupEc2MetadataServer([]ImdsReqRes{azQueryImdsReqRes, azIDQueryImdsReqRes, tokenQueryImdsReqRes}, 200*time.Millisecond)
	defer srv.Close()
	os.Setenv(ec2MetadataUriEnvForTesting, srv.URL)
	defer os.Unsetenv(ec2MetadataUriEnvForTesting)

	az, err := getEc2InstanceMetadata(azQuery)
	assert.Nil(t, err)
	assert.NotNil(t, az)
	assert.Equal(t, "us-west-2d", az)

	azID, err := getEc2InstanceMetadata(azIDQuery)
	assert.Nil(t, err)
	assert.NotNil(t, azID)
	assert.Equal(t, "usw2-az2", azID)
}

func TestBuildEcsLaunchType(t *testing.T) {
	setup()
	os.Setenv(ecsExecutionEnvVar, "AWS_ECS_FARGATE")
	defer os.Unsetenv(ecsExecutionEnvVar)
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

func TestBuildEcsContainerInstanceArn(t *testing.T) {
	setup()
	os.Setenv(ecsExecutionEnvVar, "AWS_ECS_EC2")
	os.Setenv(ecsContainerInstanceArnEnvVar, "testArn")
	defer os.Unsetenv(ecsExecutionEnvVar)
	defer os.Unsetenv(ecsContainerInstanceArnEnvVar)
	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)

	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	ecsPlatformMap := platformMap["ecsPlatformInfo"].(map[string]interface{})
	assert.NotNil(t, ecsPlatformMap)
	assert.Equal(t, 2, len(ecsPlatformMap))
	assert.NotNil(t, ecsPlatformMap["ecsLaunchType"])
	assert.Equal(t, "AWS_ECS_EC2", ecsPlatformMap["ecsLaunchType"])
	assert.NotNil(t, ecsPlatformMap["ecsContainerInstanceArn"])
	assert.Equal(t, "testArn", ecsPlatformMap["ecsContainerInstanceArn"])
}

func TestBuildEcsPlatformMap(t *testing.T) {
	setup()
	srvEcs := setupEcsMetadataServer()
	defer srvEcs.Close()

	os.Setenv(ecsExecutionEnvVar, "AWS_ECS_FARGATE")
	os.Setenv(ecsContainerMetadataUriEnv, srvEcs.URL+"/ecsmetadata/default")
	defer os.Unsetenv(ecsExecutionEnvVar)
	defer os.Unsetenv(ecsContainerMetadataUriEnv)

	md, err := BuildMetadata()

	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)
	ecsPlatformMap := platformMap["ecsPlatformInfo"].(map[string]interface{})
	assert.NotNil(t, ecsPlatformMap)
	assert.Equal(t, 5, len(ecsPlatformMap))
	assert.NotNil(t, ecsPlatformMap["ecsLaunchType"])
	assert.Equal(t, "AWS_ECS_FARGATE", ecsPlatformMap["ecsLaunchType"])
	assert.NotNil(t, ecsPlatformMap["ecsClusterArn"])
	assert.Equal(t, "TestCluster", ecsPlatformMap["ecsClusterArn"])
	assert.NotNil(t, ecsPlatformMap["ecsTaskArn"])
	assert.Equal(t, "TestTask", ecsPlatformMap["ecsTaskArn"])
	assert.NotNil(t, ecsPlatformMap["CPU"])
	assert.Equal(t, "5", ecsPlatformMap["CPU"])
	assert.NotNil(t, ecsPlatformMap["Memory"])
	assert.Equal(t, "0.25", ecsPlatformMap["Memory"])

	assert.NotNil(t, platformMap["AvailabilityZone"])
	assert.Equal(t, "us-west-2d", platformMap["AvailabilityZone"])
}

func TestBuildSupportedIPFamilies(t *testing.T) {
	setup()
	srv := setupEcsMetadataServer()
	defer srv.Close()

	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/ipv4")
	os.Setenv(ecsExecutionEnvVar, "AWS_ECS_FARGATE")
	defer os.Unsetenv(ecsContainerMetadataUriEnv)
	defer os.Unsetenv(ecsExecutionEnvVar)

	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)

	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies := platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "IPv4_ONLY", supportedIPFamilies)

	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/ipv6")
	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies = platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "IPv6_ONLY", supportedIPFamilies)

	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/all")
	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies = platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "ALL", supportedIPFamilies)

	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/NoIp")
	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	assert.Nil(t, platformMap["supportedIPFamilies"])

	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/NoNetworks")
	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	assert.Nil(t, platformMap["supportedIPFamilies"])

	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/default")
	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	assert.Nil(t, platformMap["supportedIPFamilies"])
}

func TestBuildSupportedIPFamiliesBridgeMode(t *testing.T) {
	setup()
	srv := setupEcsBridgeModeMetadataServer()
	defer srv.Close()

	// Test bridge mode with CNI_PAUSE container having IPv4 only
	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/bridge/ipv4")
	os.Setenv(ecsExecutionEnvVar, "AWS_ECS_EC2")
	defer os.Unsetenv(ecsContainerMetadataUriEnv)
	defer os.Unsetenv(ecsExecutionEnvVar)

	md, err := BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)

	platformMap := (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies := platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "IPv4_ONLY", supportedIPFamilies)

	// Test bridge mode with CNI_PAUSE container having both IPv4 and IPv6, APPNET mapping with IPv4
	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/bridge/dual")
	os.Setenv("APPNET_CONTAINER_IP_MAPPING", `{"nginx-client":"172.17.0.5","web-client":"172.17.0.7"}`)
	defer os.Unsetenv("APPNET_CONTAINER_IP_MAPPING")

	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies = platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "ALL", supportedIPFamilies)

	// Test bridge mode with CNI_PAUSE container having both IPv4 and IPv6, APPNET mapping with IPv6
	os.Setenv("APPNET_CONTAINER_IP_MAPPING", `{"nginx-client":"2001:db8:1::242:ac11:5","web-client":"2001:db8:1::242:ac11:7"}`)

	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies = platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "IPv6_ONLY", supportedIPFamilies)

	// Test bridge mode where first container has invalid network mode but second container has valid bridge mode
	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/bridge/networkmode-iteration")
	os.Unsetenv("APPNET_CONTAINER_IP_MAPPING") // Clear previous mapping

	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies = platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "IPv4_ONLY", supportedIPFamilies)

	// Test case where a container has multiple networks, with the second network having a valid mode
	os.Setenv(ecsContainerMetadataUriEnv, srv.URL+"/ecsmetadata/awsvpc/multiple-networks")
	os.Unsetenv("APPNET_CONTAINER_IP_MAPPING") // Clear previous mapping

	md, err = BuildMetadata()
	assert.Nil(t, err)
	assert.NotNil(t, md)
	platformMap = (*md)["aws.appmesh.platformInfo"].(map[string]interface{})
	assert.NotNil(t, platformMap)

	supportedIPFamilies = platformMap["supportedIPFamilies"].(string)
	assert.Equal(t, "ALL", supportedIPFamilies) // awsvpc mode with both IPv4 and IPv6
}
