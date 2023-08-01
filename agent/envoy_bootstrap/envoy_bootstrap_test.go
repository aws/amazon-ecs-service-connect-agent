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

package bootstrap

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-app-mesh-agent/agent/config"

	boot "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	trace "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"

	"github.com/ghodss/yaml"
	"github.com/nsf/jsondiff"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func setup() {
	os.Clearenv()
}

type mockFileUtil struct {
	data []byte
	path string
	err  error
}

func newMockFileUtil(data []byte, err error) *mockFileUtil {
	return &mockFileUtil{data: data, err: err}
}

func (f *mockFileUtil) Read(path string) ([]byte, error) {
	return f.data, f.err
}

func (f *mockFileUtil) Write(path string, data []byte, perm fs.FileMode) error {
	f.path = path
	f.data = data
	return f.err
}

func compareMessage(t *testing.T, m proto.Message, y string) (jsondiff.Difference, string) {
	expected, err := yaml.YAMLToJSON([]byte(strings.TrimSpace(y)))
	if err != nil {
		t.Error(err)
	}
	actual, err := protojson.Marshal(m)
	if err != nil {
		t.Error(err)
	}
	opts := jsondiff.DefaultConsoleOptions()
	result, diff := jsondiff.Compare(actual, expected, &opts)
	return result, diff
}

func checkMessage(t *testing.T, m proto.Message, y string) {
	result, diff := compareMessage(t, m, y)
	if result != jsondiff.FullMatch {
		t.Errorf("Messages do not match. Diff from expected to actual: %s\n", diff)
	}
}

func checkMessageSupersetMatch(t *testing.T, m proto.Message, y string) {
	result, diff := compareMessage(t, m, y)
	if result != jsondiff.SupersetMatch {
		t.Errorf("Expected message is not superset of actual message. Diff from expected to actual: %s\n", diff)
	}
}

func compareYaml(t *testing.T, x, y []byte) {
	expected, err := yaml.YAMLToJSON(x)
	if err != nil {
		t.Error(err)
	}
	actual, err := yaml.YAMLToJSON(y)
	if err != nil {
		t.Error(err)
	}
	compareJson(t, expected, actual)
}

func compareJson(t *testing.T, expected, actual []byte) {
	opts := jsondiff.DefaultConsoleOptions()
	result, diff := jsondiff.Compare(expected, actual, &opts)
	if result != jsondiff.FullMatch {
		t.Errorf("Messages do not match. Diff from expected to actual: %s", diff)
	}
}

func assertEquals(t *testing.T, expected interface{}, actual interface{}) {
	if expected != actual {
		t.Errorf("Expected %#v, instead got %#v", expected, actual)
	}
}

func assertError(t *testing.T, val interface{}, err error) {
	if err == nil {
		t.Errorf("Expected an error, instead got %#v", val)
	}
}

func TestGetResourceFromNodeId_ObviousBadARN(t *testing.T) {
	setup()
	res, err := getMeshResourceFromNodeId("not an arn")
	assertError(t, res, err)
}

func TestGetResourceFromNodeId_SnakeCasing(t *testing.T) {
	setup()
	res, err := getMeshResourceFromNodeId("mesh/meshName/resourceType/resourceName")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "meshName", res.MeshName)
}
func TestGetRegion_Defined(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	region, err := getRegion()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "us-west-2", region)
}

func TestGetRegionalXdsEndpoint_EndpointSet(t *testing.T) {
	setup()
	os.Setenv("APPMESH_XDS_ENDPOINT", "foo")
	defer os.Unsetenv("APPMESH_XDS_ENDPOINT")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "foo", *v)
}

func TestGetRegionalXdsEndpoint(t *testing.T) {
	setup()
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-envoy-management.us-west-2.amazonaws.com:443", *v)
}

func TestGetRegionalXdsEndpoint_China(t *testing.T) {
	setup()
	v, err := getRegionalXdsEndpoint("cn-north-1")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-envoy-management.cn-north-1.amazonaws.com.cn:443", *v)
}

func TestGetRegionalXdsEndpoint_Preview(t *testing.T) {
	setup()
	os.Setenv("APPMESH_PREVIEW", "1")
	defer os.Unsetenv("APPMESH_PREVIEW")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-preview-envoy-management.us-west-2.amazonaws.com:443", *v)
}

func TestGetRegionalXdsEndpoint_Dualstack(t *testing.T) {
	setup()
	os.Setenv("APPMESH_DUALSTACK_ENDPOINT", "1")
	defer os.Unsetenv("APPMESH_DUALSTACK_ENDPOINT")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-envoy-management.us-west-2.api.aws:443", *v)
}

func TestGetRegionalXdsEndpoint_China_Dualstack(t *testing.T) {
	setup()
	os.Setenv("APPMESH_DUALSTACK_ENDPOINT", "1")
	defer os.Unsetenv("APPMESH_DUALSTACK_ENDPOINT")
	v, err := getRegionalXdsEndpoint("cn-north-1")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-envoy-management.cn-north-1.api.amazonwebservices.com.cn:443", *v)
}

func TestGetRegionalXdsEndpoint_China_Dualstack_Preview(t *testing.T) {
	setup()
	os.Setenv("APPMESH_DUALSTACK_ENDPOINT", "1")
	os.Setenv("APPMESH_PREVIEW", "1")
	defer os.Unsetenv("APPMESH_DUALSTACK_ENDPOINT")
	defer os.Unsetenv("APPMESH_PREVIEW")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-preview-envoy-management.us-west-2.api.aws:443", *v)
}

func TestGetRegionalXdsEndpoint_Fips(t *testing.T) {
	setup()
	os.Setenv("APPMESH_FIPS_ENDPOINT", "1")
	defer os.Unsetenv("APPMESH_FIPS_ENDPOINT")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-envoy-management-fips.us-west-2.amazonaws.com:443", *v)
}

func TestGetRegionalXdsEndpoint_Fips_Dualstack(t *testing.T) {
	setup()
	os.Setenv("APPMESH_FIPS_ENDPOINT", "1")
	os.Setenv("APPMESH_DUALSTACK_ENDPOINT", "1")
	defer os.Unsetenv("APPMESH_FIPS_ENDPOINT")
	defer os.Unsetenv("APPMESH_DUALSTACK_ENDPOINT")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-envoy-management-fips.us-west-2.api.aws:443", *v)
}

func TestGetRegionalXdsEndpoint_Preview_Fips_Dualstack(t *testing.T) {
	setup()
	os.Setenv("APPMESH_PREVIEW", "1")
	os.Setenv("APPMESH_FIPS_ENDPOINT", "1")
	os.Setenv("APPMESH_DUALSTACK_ENDPOINT", "1")
	defer os.Unsetenv("APPMESH_FIPS_ENDPOINT")
	defer os.Unsetenv("APPMESH_DUALSTACK_ENDPOINT")
	defer os.Unsetenv("APPMESH_PREVIEW")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-preview-envoy-management-fips.us-west-2.api.aws:443", *v)
}
func TestGetRegionalXdsEndpoint_Preview_Fips(t *testing.T) {
	setup()
	os.Setenv("APPMESH_PREVIEW", "1")
	os.Setenv("APPMESH_FIPS_ENDPOINT", "1")
	defer os.Unsetenv("APPMESH_FIPS_ENDPOINT")
	defer os.Unsetenv("APPMESH_PREVIEW")
	v, err := getRegionalXdsEndpoint("us-west-2")
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-preview-envoy-management-fips.us-west-2.amazonaws.com:443", *v)
}

func TestGetSigningName_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_SIGNING_NAME", "foo")
	v, err := getSigningName()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "foo", v)
}

func TestGetSigningName_NotDefined(t *testing.T) {
	setup()
	v, err := getSigningName()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh", v)
}

func TestGetSigningName_NotDefined_Preview(t *testing.T) {
	setup()
	os.Setenv("APPMESH_PREVIEW", "1")
	v, err := getSigningName()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "appmesh-preview", v)
}

func TestGetNodeId_ResourceArn_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	id, err := getNodeId()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "mesh/foo/virtualNode/bar", id)
}

func TestGetNodeId_ResourceName_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_RESOURCE_NAME", "mesh/foo/virtualNode/bar")
	id, err := getNodeId()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "mesh/foo/virtualNode/bar", id)
}

func TestGetNodeId_VirtualNodeName_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_VIRTUAL_NODE_NAME", "mesh/foo/virtualNode/bar")
	id, err := getNodeId()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "mesh/foo/virtualNode/bar", id)
}

func TestGetNodeId_ResourceName_And_VirtualNodeName_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_RESOURCE_NAME", "mesh/foo/virtualNode/bar")
	os.Setenv("APPMESH_VIRTUAL_NODE_NAME", "doesnotmatter")
	id, err := getNodeId()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "mesh/foo/virtualNode/bar", id)
}

func TestGetNodeId_All_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("APPMESH_RESOURCE_NAME", "whatsinthename")
	os.Setenv("APPMESH_VIRTUAL_NODE_NAME", "namedoesnotmatter")
	id, err := getNodeId()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "mesh/foo/virtualNode/bar", id)
}

func TestGetNodeId_NothingDefined(t *testing.T) {
	setup()
	id, err := getNodeId()
	assertError(t, id, err)
}

func TestGetNodeCluster_ResourceCluster_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_RESOURCE_CLUSTER", "resource_cluster")
	cluster := getNodeCluster("foo")
	assertEquals(t, "resource_cluster", cluster)
}

func TestGetNodeCluster_VirtulNodeCluster_Defined(t *testing.T) {
	setup()
	os.Setenv("APPMESH_VIRTUAL_NODE_CLUSTER", "node_cluster")
	cluster := getNodeCluster("foo")
	assertEquals(t, "node_cluster", cluster)
}

func TestGetNodeCluster_Nothing_Defined(t *testing.T) {
	setup()
	cluster := getNodeCluster("node_id")
	assertEquals(t, "node_id", cluster)
}

func TestBuildTcpSocketAddr(t *testing.T) {
	setup()
	addr := buildTcpSocketAddr("1.2.3.4", 1234, false)
	checkMessage(t, addr, `
socketAddress:
  address: 1.2.3.4
  portValue: 1234
`)
}

func TestBuildTcpSocketAddr_IPv4Compat_Enabled(t *testing.T) {
	setup()
	addr := buildTcpSocketAddr("::", 1234, true)
	checkMessage(t, addr, `
socketAddress:
  address: "::"
  portValue: 1234
  ipv4Compat: true
`)
}

func TestBuildUdpSocketAddr(t *testing.T) {
	setup()
	addr := buildUdpSocketAddr("1.2.3.4", 1234)
	checkMessage(t, addr, `
socketAddress:
  protocol: UDP
  address: 1.2.3.4
  portValue: 1234
`)
}

func TestBuildSocketPath(t *testing.T) {
	setup()
	addr := buildSocketPipe("/data/app/tmp/statd.sock")
	checkMessage(t, addr, `
pipe:
  path: /data/app/tmp/statd.sock
`)
}

func TestBuildAdmin_Default(t *testing.T) {
	setup()
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	m, err := buildAdmin(agentConfig)
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, m, `
accessLog:
- typedConfig:
    "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
    path: "/tmp/envoy_admin_access.log"
address:
  socketAddress:
    address: 0.0.0.0
    portValue: 9901
`)
}

func TestBuildAdmin_CustomPort(t *testing.T) {
	setup()
	os.Setenv("ENVOY_ADMIN_ACCESS_PORT", "1234")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	m, err := buildAdmin(agentConfig)
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, m, `
accessLog:
- typedConfig:
    "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
    path: "/tmp/envoy_admin_access.log"
address:
  socketAddress:
    address: 0.0.0.0
    portValue: 1234
`)
}

func TestBuildAdmin_UDSPath(t *testing.T) {
	setup()
	os.Setenv("ENVOY_ADMIN_MODE", "uds")
	defer os.Unsetenv("ENVOY_ADMIN_MODE")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	m, err := buildAdmin(agentConfig)
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, m, `
accessLog:
- typedConfig:
    "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
    path: "/tmp/envoy_admin_access.log"
address:
  pipe:
    path: /tmp/envoy_admin.sock
    mode: 384
`)
}

// Envoy Admin mode will not honor APPNET_AGENT_ADMIN_MODE
// When `ENVOY_ADMIN_MODE` is not set, it will use default tcp mode.
func TestBuildAdmin_AppNetUDSPath(t *testing.T) {
	setup()
	os.Setenv("APPNET_AGENT_ADMIN_MODE", "uds")
	defer os.Unsetenv("APPNET_AGENT_ADMIN_MODE")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	m, err := buildAdmin(agentConfig)
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, m, `
accessLog:
- typedConfig:
    "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
    path: "/tmp/envoy_admin_access.log"
address:
  socketAddress:
    address: 0.0.0.0
    portValue: 9901
`)
}

func TestBuildAdmin_CustomLogFile(t *testing.T) {
	setup()
	os.Setenv("ENVOY_ADMIN_ACCESS_LOG_FILE", "/dev/stdout")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	m, err := buildAdmin(agentConfig)
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, m, `
accessLog:
- typedConfig:
    "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
    path: "/dev/stdout"
address:
  socketAddress:
    address: 0.0.0.0
    portValue: 9901
`)
}

func TestBuildAdmin_Enable_Ipv6(t *testing.T) {
	setup()
	os.Setenv("ENVOY_ADMIN_ACCESS_ENABLE_IPV6", "true")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	m, err := buildAdmin(agentConfig)
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, m, `
accessLog:
- typedConfig:
    "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
    path: "/tmp/envoy_admin_access.log"
address:
  socketAddress:
    address: "::"
    portValue: 9901
    ipv4Compat: true
`)
}

func TestBuildNode(t *testing.T) {
	setup()
	metadata := structpb.NewNullValue().GetStructValue()
	checkMessage(t, buildNode("id", "cluster", metadata), `
id: id
cluster: cluster
`)
}

func TestBuildNodeMetadata_ContainerIPMapping(t *testing.T) {
	setup()
	os.Setenv("APPNET_CONTAINER_IP_MAPPING", `{"C1":"172.10.1.1","C2":"172.10.1.2"}`)
	defer os.Unsetenv("APPNET_CONTAINER_IP_MAPPING")
	metadata, err := buildMetadataForNode()
	assert.Nil(t, err)
	// ignore metadata: aws.appmesh.platformInfo & aws.appmesh.task.interfaces
	checkMessageSupersetMatch(t, buildNode("id", "cluster", metadata), `
id: id
cluster: cluster
metadata:
  aws.ecs.serviceconnect.ClusterIPMapping:
    C1: 172.10.1.1
    C2: 172.10.1.2
`)
}

func TestBuildNodeMetadata_ListenerPortMapping(t *testing.T) {
	setup()
	os.Setenv("APPNET_LISTENER_PORT_MAPPING", `{"Listener1":15000,"Listener2":15001}`)
	defer os.Unsetenv("APPNET_LISTENER_PORT_MAPPING")
	metadata, err := buildMetadataForNode()
	assert.Nil(t, err)
	// ignore metadata: aws.appmesh.platformInfo & aws.appmesh.task.interfaces
	checkMessageSupersetMatch(t, buildNode("id", "cluster", metadata), `
id: id
cluster: cluster
metadata:
  aws.ecs.serviceconnect.ListenerPortMapping:
    Listener1: 15000
    Listener2: 15001
`)
}

func TestBuildLayeredRuntime(t *testing.T) {
	setup()
	rt, err := buildLayeredRuntime()
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, rt, `
layers:
  - name: "static_layer_0"
    staticLayer:
      envoy.features.enable_all_deprecated_features: true
      envoy.reloadable_features.http_set_tracing_decision_in_request_id: true
      envoy.reloadable_features.no_extension_lookup_by_name: true
      envoy.reloadable_features.tcp_pool_idle_timeout: true
      envoy.reloadable_features.sanitize_original_path: true
      envoy.reloadable_features.successful_active_health_check_uneject_host: false
      re2.max_program_size.error_level: 1000
  - name: "admin_layer"
    adminLayer: {}
`)
}

func TestBuildLayeredRuntime_DisableTracingDecisionHeaderMutation(t *testing.T) {
	setup()
	os.Setenv("APPMESH_SET_TRACING_DECISION", "false")
	defer os.Unsetenv("APPMESH_SET_TRACING_DECISION")
	rt, err := buildLayeredRuntime()
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, rt, `
layers:
  - name: "static_layer_0"
    staticLayer:
      envoy.features.enable_all_deprecated_features: true
      envoy.reloadable_features.http_set_tracing_decision_in_request_id: false
      envoy.reloadable_features.no_extension_lookup_by_name: true
      envoy.reloadable_features.tcp_pool_idle_timeout: true
      envoy.reloadable_features.sanitize_original_path: true
      envoy.reloadable_features.successful_active_health_check_uneject_host: false
      re2.max_program_size.error_level: 1000
  - name: "admin_layer"
    adminLayer: {}
`)
}

func TestBuildLayeredRuntime_DisableNoExtensionLookupByName(t *testing.T) {
	setup()
	os.Setenv("ENVOY_NO_EXTENSION_LOOKUP_BY_NAME", "false")
	defer os.Unsetenv("ENVOY_NO_EXTENSION_LOOKUP_BY_NAME")
	rt, err := buildLayeredRuntime()
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, rt, `
layers:
  - name: "static_layer_0"
    staticLayer:
      envoy.features.enable_all_deprecated_features: true
      envoy.reloadable_features.http_set_tracing_decision_in_request_id: true
      envoy.reloadable_features.no_extension_lookup_by_name: false
      envoy.reloadable_features.tcp_pool_idle_timeout: true
      envoy.reloadable_features.sanitize_original_path: true
      envoy.reloadable_features.successful_active_health_check_uneject_host: false
      re2.max_program_size.error_level: 1000
  - name: "admin_layer"
    adminLayer: {}
`)
}

func TestBuildLayeredRuntime_DisableTcpPoolIdleTimeout(t *testing.T) {
	setup()
	os.Setenv("ENVOY_ENABLE_TCP_POOL_IDLE_TIMEOUT", "false")
	defer os.Unsetenv("ENVOY_ENABLE_TCP_POOL_IDLE_TIMEOUT")
	rt, err := buildLayeredRuntime()
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, rt, `
layers:
  - name: "static_layer_0"
    staticLayer:
      envoy.features.enable_all_deprecated_features: true
      envoy.reloadable_features.http_set_tracing_decision_in_request_id: true
      envoy.reloadable_features.no_extension_lookup_by_name: true
      envoy.reloadable_features.tcp_pool_idle_timeout: false
      envoy.reloadable_features.sanitize_original_path: true
      envoy.reloadable_features.successful_active_health_check_uneject_host: false
      re2.max_program_size.error_level: 1000
  - name: "admin_layer"
    adminLayer: {}
`)
}

func TestBuildLayeredRuntime_DontSanitizeOriginalPath(t *testing.T) {
	setup()
	os.Setenv("ENVOY_SANITIZE_ORIGINAL_PATH", "false")
	defer os.Unsetenv("ENVOY_SANITIZE_ORIGINAL_PATH")
	rt, err := buildLayeredRuntime()
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, rt, `
layers:
  - name: "static_layer_0"
    staticLayer:
      envoy.features.enable_all_deprecated_features: true
      envoy.reloadable_features.http_set_tracing_decision_in_request_id: true
      envoy.reloadable_features.no_extension_lookup_by_name: true
      envoy.reloadable_features.tcp_pool_idle_timeout: true
      envoy.reloadable_features.sanitize_original_path: false
      envoy.reloadable_features.successful_active_health_check_uneject_host: false
      re2.max_program_size.error_level: 1000
  - name: "admin_layer"
    adminLayer: {}
`)
}

func TestBuildLayeredRuntime_ActiveHealthcheckUnejectHost(t *testing.T) {
	setup()
	os.Setenv("ENVOY_ACTIVE_HEALTH_CHECK_UNEJECT_HOST", "true")
	defer os.Unsetenv("ENVOY_ACTIVE_HEALTH_CHECK_UNEJECT_HOST")
	rt, err := buildLayeredRuntime()
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, rt, `
layers:
  - name: "static_layer_0"
    staticLayer:
      envoy.features.enable_all_deprecated_features: true
      envoy.reloadable_features.http_set_tracing_decision_in_request_id: true
      envoy.reloadable_features.no_extension_lookup_by_name: true
      envoy.reloadable_features.tcp_pool_idle_timeout: true
      envoy.reloadable_features.sanitize_original_path: true
      envoy.reloadable_features.successful_active_health_check_uneject_host: true
      re2.max_program_size.error_level: 1000
  - name: "admin_layer"
    adminLayer: {}
`)
}

func TestBuildClusterManager(t *testing.T) {
	setup()
	checkMessage(t, buildClusterManager(), `
outlierDetection:
  eventLogPath: /dev/stdout
`)
}

func TestBuildClusterManager_CustomOutlierDetection(t *testing.T) {
	setup()
	os.Setenv("ENVOY_OUTLIER_DETECTION_EVENT_LOG_PATH", "/custom/path")
	checkMessage(t, buildClusterManager(), `
outlierDetection:
  eventLogPath: /custom/path
`)
}

func TestBuildFileDataSource(t *testing.T) {
	setup()
	checkMessage(t, buildFileDataSource("/path/to/file"), `
filename: /path/to/file
`)
}

func TestBuildRegionalDynamicResources(t *testing.T) {
	setup()
	cfg, err := buildRegionalDynamicResources("endpoint", "region", "signing_name")
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, cfg, `
adsConfig:
  transportApiVersion: V3
  apiType: GRPC
  grpcServices:
  - googleGrpc:
      statPrefix: ads
      targetUri: endpoint
      channelCredentials:
        sslCredentials:
          rootCerts:
            filename: /etc/pki/tls/cert.pem
      credentialsFactoryName: envoy.grpc_credentials.aws_iam
      callCredentials:
      - fromPlugin:
          name: envoy.grpc_credentials.aws_iam
          typedConfig:
            "@type": type.googleapis.com/envoy.config.grpc_credential.v3.AwsIamConfig
            serviceName: signing_name
            region: region
      channelArgs:
        args:
          grpc.http2.max_pings_without_data: { intValue: "0" }
          grpc.keepalive_time_ms: { intValue: "10000" }
          grpc.keepalive_timeout_ms: { intValue: "20000" }

cdsConfig:
  ads: {}
  initialFetchTimeout: 0s
  resourceApiVersion: V3

ldsConfig:
  ads: {}
  initialFetchTimeout: 0s
  resourceApiVersion: V3
`)
}

func TestBuildDynamicResourcesForRelayEndpoint(t *testing.T) {
	setup()
	cfg, err := buildDynamicResourcesForRelayEndpoint("unix:///tmp/xds-envoy-test.sock")
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, cfg, `
adsConfig:
  transportApiVersion: V3
  apiType: GRPC
  grpcServices:
  - googleGrpc:
      statPrefix: ads
      targetUri: unix:///tmp/xds-envoy-test.sock
      channelArgs:
        args:
          grpc.http2.max_pings_without_data: { intValue: "0" }
          grpc.keepalive_time_ms: { intValue: "10000" }
          grpc.keepalive_timeout_ms: { intValue: "20000" }

cdsConfig:
  ads: {}
  initialFetchTimeout: 0s
  resourceApiVersion: V3

ldsConfig:
  ads: {}
  initialFetchTimeout: 0s
  resourceApiVersion: V3
`)
}

func TestBuildDynamicResourcesForRelayEndpoint_MalformedFetchTimeout(t *testing.T) {
	setup()
	os.Setenv("ENVOY_INITIAL_FETCH_TIMEOUT", "6notaninteger")
	cfg, err := buildDynamicResourcesForRelayEndpoint("endpoint")
	assertError(t, cfg, err)
}

func TestBuildRegionalDynamicResources_MalformedFetchTimeout(t *testing.T) {
	setup()
	os.Setenv("ENVOY_INITIAL_FETCH_TIMEOUT", "6notaninteger")
	cfg, err := buildRegionalDynamicResources("endpoint", "region", "appmesh")
	assertError(t, cfg, err)
}

func TestBuildDynamicResourcesForRelayEndpoint_CustomFetchTimeout(t *testing.T) {
	setup()
	os.Setenv("ENVOY_INITIAL_FETCH_TIMEOUT", "180")

	cfg, err := buildDynamicResourcesForRelayEndpoint("unix:///tmp/xds-envoy-test.sock")
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, cfg, `
adsConfig:
  transportApiVersion: V3
  apiType: GRPC
  grpcServices:
  - googleGrpc:
      statPrefix: ads
      targetUri: unix:///tmp/xds-envoy-test.sock
      channelArgs:
        args:
          grpc.http2.max_pings_without_data: { intValue: "0" }
          grpc.keepalive_time_ms: { intValue: "10000" }
          grpc.keepalive_timeout_ms: { intValue: "20000" }

cdsConfig:
  ads: {}
  initialFetchTimeout: 180s
  resourceApiVersion: V3

ldsConfig:
  ads: {}
  initialFetchTimeout: 180s
  resourceApiVersion: V3
`)
}

func TestBuildRegionalDynamicResources_CustomFetchTimeout(t *testing.T) {
	setup()
	os.Setenv("ENVOY_INITIAL_FETCH_TIMEOUT", "180")
	cfg, err := buildRegionalDynamicResources("endpoint", "region", "signing_name")
	if err != nil {
		t.Error(err)
	}
	checkMessage(t, cfg, `
adsConfig:
  transportApiVersion: V3
  apiType: GRPC
  grpcServices:
  - googleGrpc:
      statPrefix: ads
      targetUri: endpoint
      channelCredentials:
        sslCredentials:
          rootCerts:
            filename: /etc/pki/tls/cert.pem
      credentialsFactoryName: envoy.grpc_credentials.aws_iam
      callCredentials:
      - fromPlugin:
          name: envoy.grpc_credentials.aws_iam
          typedConfig:
            "@type": type.googleapis.com/envoy.config.grpc_credential.v3.AwsIamConfig
            serviceName: signing_name
            region: region
      channelArgs:
        args:
          grpc.http2.max_pings_without_data: { intValue: "0" }
          grpc.keepalive_time_ms: { intValue: "10000" }
          grpc.keepalive_timeout_ms: { intValue: "20000" }

cdsConfig:
  ads: {}
  initialFetchTimeout: 180s
  resourceApiVersion: V3

ldsConfig:
  ads: {}
  initialFetchTimeout: 180s
  resourceApiVersion: V3
`)
}

func TestGetXRayAddressAndPort_BadXRayPort(t *testing.T) {
	setup()
	os.Setenv("XRAY_DAEMON_PORT", "6notaninteger")
	addr, port, err := getXRayAddressAndPort()
	assertError(t, fmt.Sprintf("%s:%d", addr, port), err)
}

func TestGetXRayAddressAndPort_NonIPAddress(t *testing.T) {
	setup()
	os.Setenv("AWS_XRAY_DAEMON_ADDRESS", "xray-daemon:1234")
	addr, port, err := getXRayAddressAndPort()
	assertError(t, fmt.Sprintf("%s:%d", addr, port), err)
}

func TestGetXRayAddressAndPort_PortOverrideDefaultAddress(t *testing.T) {
	setup()
	os.Setenv("XRAY_DAEMON_PORT", "1234")
	addr, port, err := getXRayAddressAndPort()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "127.0.0.1", addr)
	assertEquals(t, 1234, port)
}

func TestGetXRayAddressAndPort_AddressOverrideNoPort(t *testing.T) {
	setup()
	os.Setenv("AWS_XRAY_DAEMON_ADDRESS", "1.2.3.4")
	addr, port, err := getXRayAddressAndPort()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "1.2.3.4", addr)
	assertEquals(t, 2000, port)
}

func TestGetXRayAddressAndPort_AddressOverrideWithPort(t *testing.T) {
	setup()
	os.Setenv("AWS_XRAY_DAEMON_ADDRESS", "1.2.3.4:1234")
	addr, port, err := getXRayAddressAndPort()
	if err != nil {
		t.Error(err)
	}
	assertEquals(t, "1.2.3.4", addr)
	assertEquals(t, 1234, port)
}

func TestGetXraySamplingRuleManifest_EmptyEnv(t *testing.T) {
	setup()
	// Env XRAY_SAMPLING_RULE_MANIFEST is not explicitly set
	v, err := getXraySamplingRuleManifest(nil)
	if err != nil {
		t.Error(err)
	}
	if v != "" {
		t.Errorf("Expected empty, instead got %s", v)
	}
}

func TestGetXraySamplingRuleManifest_NoFile(t *testing.T) {
	setup()
	os.Setenv("XRAY_SAMPLING_RULE_MANIFEST", "/dev/null")
	v, err := getXraySamplingRuleManifest(newMockFileUtil([]byte{}, fmt.Errorf("file not present")))
	assertError(t, v, err)
}

func TestGetXraySamplingRuleManifest_EmptyFile(t *testing.T) {
	setup()
	os.Setenv("XRAY_SAMPLING_RULE_MANIFEST", "/dev/null")
	v, err := getXraySamplingRuleManifest(newMockFileUtil([]byte{}, nil))
	assertError(t, v, err)
}

func TestGetXraySamplingRuleManifest_UnsupportedVersion(t *testing.T) {
	setup()
	data := []byte(`
{
  "version": 1,
  "default": {
    "fixed_target": 1,
    "rate": 0.1
  }
}
`)
	os.Setenv("XRAY_SAMPLING_RULE_MANIFEST", "/dev/null")
	v, err := getXraySamplingRuleManifest(newMockFileUtil(data, nil))
	assertError(t, v, err)
}

func TestGetXraySamplingRuleManifest(t *testing.T) {
	setup()
	data := []byte(`
{
  "version": 2,
  "default": {
    "fixed_target": 1,
    "rate": 0.1
  }
}
`)
	const validFilePath = "validFilePath"
	os.Setenv("XRAY_SAMPLING_RULE_MANIFEST", "validFilePath")
	if v, err := getXraySamplingRuleManifest(newMockFileUtil(data, nil)); err != nil {
		t.Error(err)
	} else if validFilePath != v {
		t.Errorf("returned value:%s is not what expected:%s", v, validFilePath)
	}
}

func TestGetXraySamplingRate_EmptyEnv(t *testing.T) {
	setup()
	// Env XRAY_SAMPLING_RATE is not explicitly set
	v, err := getXraySamplingRuleManifest(nil)
	if err != nil {
		t.Error(err)
	}
	if v != "" {
		t.Errorf("Expected empty, instead got %s", v)
	}
}

func TestGetXraySamplingRate_BadValue(t *testing.T) {
	setup()
	os.Setenv("XRAY_SAMPLING_RATE", "notanumber")
	v, err := getXraySamplingRuleManifest(nil)
	assertError(t, v, err)
}

func TestGetXraySamplingRate_ValueOutofBound(t *testing.T) {
	setup()
	os.Setenv("XRAY_SAMPLING_RATE", "5.49")
	v, err := getXraySamplingRuleManifest(nil)
	assertError(t, v, err)
}

func TestGetXraySamplingRate_NegativeValue(t *testing.T) {
	setup()
	os.Setenv("XRAY_SAMPLING_RATE", "-0.01")
	v, err := getXraySamplingRuleManifest(nil)
	assertError(t, v, err)
}

func TestGetXraySamplingRate_WriteFailed(t *testing.T) {
	setup()
	os.Setenv("XRAY_SAMPLING_RATE", "0.03")
	v, err := getXraySamplingRuleManifest(newMockFileUtil([]byte{}, fmt.Errorf("cannot write to file")))
	assertError(t, v, err)
}

func TestGetXraySamplingRate_InDecimal(t *testing.T) {
	setup()
	os.Setenv("XRAY_SAMPLING_RATE", "0.1451")
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	if v, err := getXraySamplingRuleManifest(mockFileUtil); err != nil {
		t.Error(err)
	} else if mockFileUtil.path != v {
		t.Errorf("returned value:%s is not what expected:%s", v, mockFileUtil.path)
	}
	compareJson(t, mockFileUtil.data, []byte(`
{
  "version": 2,
  "default": {
    "service_name": "",
    "host": "",
    "http_method": "",
    "url_path": "",
    "fixed_target": 1,
    "rate": 0.15
  },
  "rules": []
}

`))
}

func TestAppendXRayTracing_BadResourceName(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendXRayTracing(b, "badName", "cluster", nil); err != nil {
		t.Error(err)
	}
	// We'll default to a generic xray config for the cluster
	checkMessage(t, b, `
tracing:
  http:
    name: envoy.tracers.xray
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.XRayConfig
      segmentName: cluster
      segmentFields:
        origin: AWS::AppMesh::Proxy
      daemonEndpoint:
        protocol: UDP
        address: 127.0.0.1
        portValue: 2000
`)
}

func TestAppendXRayTracing(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendXRayTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil); err != nil {
		t.Error(err)
	}
	// We'll default to a generic xray config
	checkMessage(t, b, `
tracing:
  http:
    name: envoy.tracers.xray
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.XRayConfig
      segmentName: foo/bar
      segmentFields:
        origin: AWS::AppMesh::Proxy
        aws:
          app_mesh:
            mesh_name: foo
            virtual_node_name: bar
      daemonEndpoint:
        protocol: UDP
        address: 127.0.0.1
        portValue: 2000
`)
}

func TestAppendXRayTracingWithCustomSegmentName(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	os.Setenv("XRAY_SEGMENT_NAME", "custom_segment_name")
	defer os.Unsetenv("XRAY_SEGMENT_NAME")
	if err := appendXRayTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil); err != nil {
		t.Error(err)
	}
	// We'll default to a generic xray config
	checkMessage(t, b, `
tracing:
  http:
    name: envoy.tracers.xray
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.XRayConfig
      segmentName: custom_segment_name
      segmentFields:
        origin: AWS::AppMesh::Proxy
        aws:
          app_mesh:
            mesh_name: foo
            virtual_node_name: bar
      daemonEndpoint:
        protocol: UDP
        address: 127.0.0.1
        portValue: 2000
`)
}

func TestAppendXRayTracing_WithSamplingManifestEnv(t *testing.T) {
	setup()
	data := []byte(`
{
  "version": 2,
  "rules": [
    {
      "description": "Player moves.",
      "host": "*",
      "http_method": "*",
      "url_path": "/api/move/*",
      "fixed_target": 0,
      "rate": 0.05
    }
  ],
  "default": {
    "fixed_target": 1,
    "rate": 0.1
  }
}
`)
	os.Setenv("XRAY_SAMPLING_RULE_MANIFEST", "/dev/null")
	b := &boot.Bootstrap{}
	if err := appendXRayTracing(b, "mesh/foo/virtualNode/bar", "cluster", newMockFileUtil(data, nil)); err != nil {
		t.Error(err)
	}
	// We'll default to a generic xray config
	checkMessage(t, b, `
tracing:
  http:
    name: envoy.tracers.xray
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.XRayConfig
      segmentName: foo/bar
      segmentFields:
        origin: AWS::AppMesh::Proxy
        aws:
          app_mesh:
            mesh_name: foo
            virtual_node_name: bar
      daemonEndpoint:
        protocol: UDP
        address: 127.0.0.1
        portValue: 2000
      samplingRuleManifest:
        filename: /dev/null
`)
}

func TestAppendXRayTracing_WithBadSamplingManifestEnv(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_XRAY_TRACING", "1")
	os.Setenv("XRAY_SAMPLING_RULE_MANIFEST", "/dev/null")
	b := &boot.Bootstrap{}
	err := appendXRayTracing(b, "mesh/foo/virtualNode/bar", "cluster", newMockFileUtil([]byte{}, fmt.Errorf("file not present")))
	assertError(t, b, err)
}

func TestAppendXRayTracing_WithSamplingRateEnv(t *testing.T) {
	setup()
	// Set XRAY_SAMPLING_RATE with a valid percentage value between 0.0 & 1.00
	os.Setenv("XRAY_SAMPLING_RATE", "0.01")
	b := &boot.Bootstrap{}
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	if err := appendXRayTracing(b, "mesh/foo/virtualNode/bar", "cluster", mockFileUtil); err != nil {
		t.Error(err)
	}
	// We'll default to a generic xray config
	checkMessage(t, b, fmt.Sprintf(`
tracing:
  http:
    name: envoy.tracers.xray
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.XRayConfig
      segmentName: foo/bar
      segmentFields:
        origin: AWS::AppMesh::Proxy
        aws:
          app_mesh:
            mesh_name: foo
            virtual_node_name: bar
      daemonEndpoint:
        protocol: UDP
        address: 127.0.0.1
        portValue: 2000
      samplingRuleManifest:
        filename: %s
`, mockFileUtil.path))
}

func TestAppendXRayTracing_WithDefaultSamplingRateEnv(t *testing.T) {
	setup()
	// Set XRAY_SAMPLING_RATE with a valid percentage value between 0.0 & 1.00
	// But no sampling manifest file generated if value is 0.05, as it is the default
	os.Setenv("XRAY_SAMPLING_RATE", "0.05")
	b := &boot.Bootstrap{}
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	if err := appendXRayTracing(b, "mesh/foo/virtualNode/bar", "cluster", mockFileUtil); err != nil {
		t.Error(err)
	}
	// We'll default to a generic xray config
	checkMessage(t, b, `
tracing:
  http:
    name: envoy.tracers.xray
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.XRayConfig
      segmentName: foo/bar
      segmentFields:
        origin: AWS::AppMesh::Proxy
        aws:
          app_mesh:
            mesh_name: foo
            virtual_node_name: bar
      daemonEndpoint:
        protocol: UDP
        address: 127.0.0.1
        portValue: 2000
`)
}

func TestAppendXRayTracing_WithBadSamplingRateEnv(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_XRAY_TRACING", "1")
	os.Setenv("XRAY_SAMPLING_RATE", "notanumber")
	b := &boot.Bootstrap{}
	err := appendXRayTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil)
	assertError(t, b, err)
}

func TestAppendDataDogTracing_BadPort(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	os.Setenv("DATADOG_TRACER_PORT", "notaport")
	assertError(t, nil, appendDataDogTracing(b, "cluster"))
}

func TestAppendDataDogTracing(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendDataDogTracing(b, "mesh/foo/virtualNode/bar"); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
staticResources:
  clusters:
    - name: datadog_agent
      type: STRICT_DNS
      connectTimeout: 1s
      loadAssignment: 
        clusterName: datadog_agent
        endpoints:
          - lbEndpoints:
              - endpoint:
                  address:
                    socketAddress:
                      address: 127.0.0.1
                      portValue: 8126

tracing:
  http:
    name: envoy.tracers.datadog
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.DatadogConfig
      collectorCluster: datadog_agent
      serviceName: envoy-foo/bar
`)
}

func TestAppendDataDogTracing_UnparsableNodeId(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendDataDogTracing(b, "1234567890"); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
staticResources:
  clusters:
    - name: datadog_agent
      type: STRICT_DNS
      connectTimeout: 1s
      loadAssignment: 
        clusterName: datadog_agent
        endpoints:
          - lbEndpoints:
              - endpoint:
                  address:
                    socketAddress:
                      address: 127.0.0.1
                      portValue: 8126

tracing:
  http:
    name: envoy.tracers.datadog
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.DatadogConfig
      collectorCluster: datadog_agent
      serviceName: envoy
`)
}

func TestAppendDataDogTracing_CustomAddrAndPort(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	os.Setenv("DATADOG_TRACER_PORT", "1234")
	os.Setenv("DATADOG_TRACER_ADDRESS", "1.2.3.4")
	if err := appendDataDogTracing(b, "mesh/foo/virtualNode/bar"); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
staticResources:
  clusters:
    - name: datadog_agent
      type: STRICT_DNS
      connectTimeout: 1s
      loadAssignment: 
        clusterName: datadog_agent
        endpoints:
          - lbEndpoints:
              - endpoint:
                  address:
                    socketAddress:
                      address: 1.2.3.4
                      portValue: 1234

tracing:
  http:
    name: envoy.tracers.datadog
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.DatadogConfig
      collectorCluster: datadog_agent
      serviceName: envoy-foo/bar
`)
}

func TestAppendDataDogTracing_CustomServiceName(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	os.Setenv("DD_SERVICE", "my-service")
	if err := appendDataDogTracing(b, "cluster"); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
staticResources:
  clusters:
    - name: datadog_agent
      type: STRICT_DNS
      connectTimeout: 1s
      loadAssignment: 
        clusterName: datadog_agent
        endpoints:
          - lbEndpoints:
              - endpoint:
                  address:
                    socketAddress:
                      address: 127.0.0.1
                      portValue: 8126

tracing:
  http:
    name: envoy.tracers.datadog
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.DatadogConfig
      collectorCluster: datadog_agent
      serviceName: my-service
`)
}

func TestAppendJaegerTracing_BadPort(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	os.Setenv("JAEGER_TRACER_PORT", "notaport")
	assertError(t, nil, appendJaegerTracing(b))
}

func TestAppendJaegerTracing(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendJaegerTracing(b); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
staticResources:
  clusters:
    - name: jaeger
      type: STRICT_DNS
      connectTimeout: 1s
      loadAssignment: 
        clusterName: jaeger
        endpoints:
          - lbEndpoints:
              - endpoint:
                  address:
                    socketAddress:
                      address: 127.0.0.1
                      portValue: 9411

tracing:
  http:
    name: envoy.tracers.zipkin
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.ZipkinConfig
      collectorCluster: jaeger
      collectorEndpoint: /api/v2/spans
      collectorEndpointVersion: HTTP_PROTO
      sharedSpanContext: false
`)
}

func TestAppendJaegarTracing_CustomAddrPortAndVersion(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	os.Setenv("JAEGER_TRACER_PORT", "1234")
	os.Setenv("JAEGER_TRACER_ADDRESS", "my-collector-otlp-collector.observability.svc.cluster.local")
	os.Setenv("JAEGER_TRACER_VERSION", "JSON")
	if err := appendJaegerTracing(b); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
staticResources:
  clusters:
    - name: jaeger
      type: STRICT_DNS
      connectTimeout: 1s
      loadAssignment: 
        clusterName: jaeger
        endpoints:
          - lbEndpoints:
              - endpoint:
                  address:
                    socketAddress:
                      address: my-collector-otlp-collector.observability.svc.cluster.local
                      portValue: 1234

tracing:
  http:
    name: envoy.tracers.zipkin
    typedConfig:
      "@type": type.googleapis.com/envoy.config.trace.v3.ZipkinConfig
      collectorCluster: jaeger
      collectorEndpoint: /api/v2/spans
      collectorEndpointVersion: HTTP_JSON
      sharedSpanContext: false
`)
}

func TestAppendSdsSocketCluster(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendSdsSocketCluster(b, "/path/to/socket"); err != nil {
		t.Error(err)
	}

	checkMessage(t, b, `
staticResources:
  clusters:
    - name: static_cluster_sds_unix_socket
      type: STATIC
      connectTimeout: 1s
      http2ProtocolOptions: {}
      loadAssignment: 
        clusterName: static_cluster_sds_unix_socket
        endpoints:
          - lbEndpoints:
              - endpoint:
                  address:
                    pipe:
                      path: /path/to/socket
`)
}

func TestMergeBootstrap_MultipleTracers(t *testing.T) {
	setup()
	b := &boot.Bootstrap{
		Tracing: &trace.Tracing{},
	}
	assertError(t, b, mergeBootstrap(b, b))
}

func TestMergeBootstrap_MultipleStatsConfigs(t *testing.T) {
	setup()
	b := &boot.Bootstrap{
		StatsConfig: &metrics.StatsConfig{},
	}
	assertError(t, b, mergeBootstrap(b, b))
}

func TestMergeBootstrap_MultipleStatsSinks(t *testing.T) {
	setup()
	b := &boot.Bootstrap{
		StatsSinks: []*metrics.StatsSink{
			&metrics.StatsSink{},
		},
	}
	if err := mergeBootstrap(b, b); err != nil {
		t.Error(err)
	}
	// There will be 2 since I merged it with itself
	checkMessage(t, b, `
statsSinks:
  - {}
  - {}
`)
}

func TestMergeBootstrap_StaticResources(t *testing.T) {
	setup()
	b := &boot.Bootstrap{
		StaticResources: &boot.Bootstrap_StaticResources{
			Clusters: []*cluster.Cluster{
				&cluster.Cluster{},
			},
			Listeners: []*listener.Listener{
				&listener.Listener{},
			},
		},
	}
	// static resources are recursively merged
	if err := mergeBootstrap(b, b); err != nil {
		t.Error(err)
	}
	// There will be 2 of each since I merged it with itself
	checkMessage(t, b, `
staticResources:
  clusters:
    - {}
    - {}
  listeners:
    - {}
    - {}
`)
}

func TestAppendTracing_XRay(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_XRAY_TRACING", "1")
	b := &boot.Bootstrap{}
	if err := appendTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil); err != nil {
		t.Error(err)
	}
}

func TestAppendTracing_DataDog(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_DATADOG_TRACING", "1")
	b := &boot.Bootstrap{}
	if err := appendTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil); err != nil {
		t.Error(err)
	}
}

func TestAppendTracing_Jaegar(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_JAEGER_TRACING", "1")
	b := &boot.Bootstrap{}
	if err := appendTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil); err != nil {
		t.Error(err)
	}
}

func TestAppendTracing_RequiresSingleProvider(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_XRAY_TRACING", "1")
	os.Setenv("ENABLE_ENVOY_DATADOG_TRACING", "1")
	b := &boot.Bootstrap{}
	assertError(t, b, appendTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil))
}

func TestAppendTracing_BadInputs(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	os.Setenv("ENABLE_ENVOY_XRAY_TRACING", "goahead")
	assertError(t, b, appendTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil))
	os.Unsetenv("ENABLE_ENVOY_XRAY_TRACING")
	os.Setenv("ENABLE_ENVOY_DATADOG_TRACING", "goahead")
	assertError(t, b, appendTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil))
	os.Unsetenv("ENABLE_ENVOY_DATADOG_TRACING")
	os.Setenv("ENABLE_ENVOY_JAEGER_TRACING", "goahead")
	assertError(t, b, appendTracing(b, "mesh/foo/virtualNode/bar", "cluster", nil))
	os.Unsetenv("ENABLE_ENVOY_JAEGER_TRACING")
}

func TestAppendStats_DisableEnvoyStatsTags(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_STATS_TAGS", "0")
	b := &boot.Bootstrap{}
	if err := appendStats(b, "mesh/foo/virtualNode/bar"); err != nil {
		t.Error(err)
	}
	y := `
statsConfig:
  statsTags:
  - regex: .*?\.ingress\.((\w+?)\.)[0-9]+?\.(.+?)$
    tagName: appmesh.listener_protocol
  - regex: .*?\.ingress\.\w+?\.(([0-9]+?)\.)(.+?)$
    tagName: appmesh.listener_port
  - regex: .*?\.ingress\.\w+?\.[0-9]+?\.rds\.((.*?)\.)(.+?)$
    tagName: envoy_rds_route_config
`
	checkMessage(t, b, y)
}

func TestAppendStats_EnableEnvoyStatsTags(t *testing.T) {
	setup()
	os.Setenv("ENABLE_ENVOY_STATS_TAGS", "1")
	b := &boot.Bootstrap{}
	if err := appendStats(b, "mesh/foo/virtualNode/bar"); err != nil {
		t.Error(err)
	}
	y := `
statsConfig:
  statsTags:
  - fixedValue: foo
    tagName: appmesh.mesh
  - fixedValue: bar
    tagName: appmesh.virtual_node
  - regex: .*?\.ingress\.((\w+?)\.)[0-9]+?\.(.+?)$
    tagName: appmesh.listener_protocol
  - regex: .*?\.ingress\.\w+?\.(([0-9]+?)\.)(.+?)$
    tagName: appmesh.listener_port
  - regex: .*?\.ingress\.\w+?\.[0-9]+?\.rds\.((.*?)\.)(.+?)$
    tagName: envoy_rds_route_config
`
	checkMessage(t, b, y)
}

func TestAppendStats_EnableMetricExtension_ServiceConnect(t *testing.T) {
	setup()
	os.Setenv("APPMESH_METRIC_EXTENSION_VERSION", "1")
	b := &boot.Bootstrap{}
	if err := appendStats(b, "arn:aws:us-west-2:ecs:123456:task-set/test-cluster/test-service/12345"); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
statsConfig:
  statsTags:
    - tagName: ServiceName
      regex: ^appmesh(?:\..+?\..+?)*(\.ServiceName\.(.+?))(?:\..+?\..+?)*\.(?:.+)$
    - tagName: ClusterName
      regex: ^appmesh(?:\..+?\..+?)*(\.ClusterName\.(.+?))(?:\..+?\..+?)*\.(?:.+)$
    - tagName: Direction
      regex: ^appmesh(?:\..+?\..+?)*(\.Direction\.(.+?))(?:\..+?\..+?)*\.(?:.+)$
    - tagName: DiscoveryName
      regex: ^appmesh(?:\..+?\..+?)*(\.DiscoveryName\.((?:(?!\.(ClusterName|ServiceName|Direction)).)+))(?:\..+?\..+?)*\.(?:.+)$
    - tagName: TargetDiscoveryName
      regex: ^appmesh(?:\..+?\..+?)*(\.TargetDiscoveryName\.((?:(?!\.(ClusterName|ServiceName|Direction)).)+))(?:\..+?\..+?)*\.(?:.+)$
`)
}

func TestAppendStatsFlushInterval(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendStatsFlushInterval(b, "15s"); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
statsFlushInterval: 15s
`)
}

func TestAppendDogStatsDSinks(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	if err := appendDogStatsDSinks(b); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
statsSinks:
  - name: envoy.stat_sinks.dog_statsd
    typedConfig:
      "@type": type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
      address:
        socketAddress:
          protocol: UDP
          address: 127.0.0.1
          portValue: 8125
`)
}

func TestAppendDogStatsDSinks_WithSocketPath(t *testing.T) {
	setup()
	os.Setenv("STATSD_SOCKET_PATH", "/data/app/tmp/statd.sock")
	b := &boot.Bootstrap{}
	if err := appendDogStatsDSinks(b); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
statsSinks:
  - name: envoy.stat_sinks.dog_statsd
    typedConfig:
      "@type": type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
      address:
        pipe:
          path: /data/app/tmp/statd.sock
`)
}

func TestAppendDogStatsDSinks_WithEmptySocketPath(t *testing.T) {
	setup()
	os.Setenv("STATSD_SOCKET_PATH", " ")
	b := &boot.Bootstrap{}
	if err := appendDogStatsDSinks(b); err != nil {
		t.Error(err)
	}
	checkMessage(t, b, `
statsSinks:
  - name: envoy.stat_sinks.dog_statsd
    typedConfig:
      "@type": type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
      address:
        socketAddress:
          portValue: 8125
          protocol: UDP
          address: 127.0.0.1
`)
}

func TestAppendDogStatsDSinksBadPortInput(t *testing.T) {
	setup()
	os.Setenv("STATSD_PORT", "TCP")
	b := &boot.Bootstrap{}
	err := appendDogStatsDSinks(b)
	assertError(t, b, err)
}

func TestAppendStatsFlushInterval_BadDuration(t *testing.T) {
	setup()
	b := &boot.Bootstrap{}
	assertError(t, b, appendStatsFlushInterval(b, "not_a_duration"))
}

func TestBootstrap(t *testing.T) {
	setup()
	// Quick sanity-check that a default bootstrap can be made
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	if _, err := bootstrap(agentConfig, newMockFileUtil([]byte{}, fmt.Errorf("should not call this function"))); err != nil {
		t.Error(err)
	}
}

func TestBootstrap_NullTracingConfigFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_TRACING_CFG_FILE", "/dev/null")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	// mocking FileUtil doesn't return error when file is empty , but still expect error after parsing.
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	b, err := bootstrap(agentConfig, mockFileUtil)
	if err != nil {
		t.Error(err)
	}
	y, err := convertToYAML(b, mockFileUtil)
	assertEquals(t, "", y)
	assertError(t, b, err)
}

func TestBootstrap_NullStatsConfigFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_CONFIG_FILE", "/dev/null")
	// mocking FileUtil doesn't return error when file is empty , but still expect error after parsing.
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	b, err := bootstrap(agentConfig, mockFileUtil)
	if err != nil {
		t.Error(err)
	}
	y, err := convertToYAML(b, mockFileUtil)
	assertEquals(t, "", y)
	assertError(t, b, err)
}

func TestBootstrap_NullStatsSinksConfigFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_SINKS_CFG_FILE", "/dev/null")
	// mocking FileUtil doesn't return error when file is empty , but still expect error after parsing.
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	b, err := bootstrap(agentConfig, mockFileUtil)
	if err != nil {
		t.Error(err)
	}
	y, err := convertToYAML(b, mockFileUtil)
	assertEquals(t, "", y)
	assertError(t, b, err)
}

func TestBootstrap_WithSdsSocketPath(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("APPMESH_SDS_SOCKET_PATH", "/path/to/socket")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	_, err := bootstrap(agentConfig, newMockFileUtil([]byte{}, fmt.Errorf("should not call this function")))
	if err != nil {
		t.Error(err)
	}
}

func TestBootstrap_WithEnableEnvoyStatsTag(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENABLE_ENVOY_STATS_TAGS", "1")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	_, err := bootstrap(agentConfig, newMockFileUtil([]byte{}, fmt.Errorf("should not call this function")))
	if err != nil {
		t.Error(err)
	}
}

func TestBootstrap_WithStatsFlushInterval(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_FLUSH_INTERVAL", "15s")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	_, err := bootstrap(agentConfig, newMockFileUtil([]byte{}, fmt.Errorf("should not call this function")))
	if err != nil {
		t.Error(err)
	}
}

func TestBootstrap_WithEnableEnvoyDogStatsd(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENABLE_ENVOY_DOG_STATSD", "1")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	_, err := bootstrap(agentConfig, newMockFileUtil([]byte{}, fmt.Errorf("should not call this function")))
	if err != nil {
		t.Error(err)
	}
}

func TestMergeMapIntfs_StaticResources(t *testing.T) {
	setup()
	var b map[string]interface{}
	data1 := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	err := yaml.Unmarshal(data1, &b)
	if err != nil {
		t.Error(err)
	}
	// static resources are recursively merged
	bootConfig, err := mergeStaticResourcesMaps(b, b)
	if err != nil {
		t.Error(err)
	}
	output, err := yaml.Marshal(bootConfig)
	if err != nil {
		t.Error(err)
	}
	// There will be 2 of each since I merged it with itself
	compareYaml(t, output, []byte(`
staticResources:
  clusters:
    - a: value
    - a: value
  listeners:
    - b: value
    - b: value
  secrets:
    - c: value
    - c: value
`))
}

func TestMergeMapIntfs_StaticResourcesDestEmpty(t *testing.T) {
	setup()
	var b map[string]interface{}
	// This will also test the condition where src key is in snake_case
	data1 := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	err := yaml.Unmarshal(data1, &b)
	if err != nil {
		t.Error(err)
	}
	bb := make(map[string]interface{})
	data2 := []byte(`
staticResources: {}
`)
	err = yaml.Unmarshal(data2, &bb)
	if err != nil {
		t.Error(err)
	}
	// static resources are recursively merged
	bootConfig, err := mergeStaticResourcesMaps(bb, b)
	if err != nil {
		t.Error(err)
	}
	output, err := yaml.Marshal(bootConfig)
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, output, []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`))
}

func TestMergeMapIntfs_StaticResourcesSrcEmpty(t *testing.T) {
	setup()
	var b map[string]interface{}
	data := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	err := yaml.Unmarshal(data, &b)
	if err != nil {
		t.Error(err)
	}
	bb := make(map[string]interface{})
	// All the keys in data2 should already be normalized to lowerCamelCase since as it is the destination and
	// any value merged to the destination so far will have the key in lowerCamelCase.
	data2 := []byte(`
staticResources:
  clusters: []
  listeners: []
  secrets: []
`)
	err = yaml.Unmarshal(data2, &bb)
	if err != nil {
		t.Error(err)
	}
	// static resources are recursively merged
	bootConfig, err := mergeStaticResourcesMaps(b, bb)
	if err != nil {
		t.Error(err)
	}
	output, err := yaml.Marshal(bootConfig)
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, output, []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`))
}

func TestMergeMapIntfs_Resources(t *testing.T) {
	setup()
	var b map[string]interface{}
	data := []byte(`
dynamic_resources:
  lds_config:
    path: value1
  cds_config:
    path: value2
  ads_config:
    path: value3
header_prefix: header_prefix_value
fatal_actions:
- config: action1
- config: action2
default_socket_interface: new_socket_value
`)
	err := yaml.Unmarshal(data, &b)
	if err != nil {
		t.Error(err)
	}
	bb := make(map[string]interface{})
	// All the keys in data2 should already be normalized to lowerCamelCase since as it is the destination and
	// any value merged to the destination so far will have the key in lowerCamelCase.
	data2 := []byte(`
staticResources:
  clusters: []
  listeners: []
  secrets: []
defaultSocketInterface: old_socket_value
headerPrefix: old_header_prefix_value
`)
	err = yaml.Unmarshal(data2, &bb)
	if err != nil {
		t.Error(err)
	}
	// All resources are replaced, so old values get overwritten.
	bootConfig, err := mergeDstMapInterfaceWithSrc(bb, b)
	if err != nil {
		t.Error(err)
	}
	output, err := yaml.Marshal(bootConfig)
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, output, []byte(`
staticResources:
  clusters: []
  listeners: []
  secrets: []
dynamicResources:
  lds_config:
    path: value1
  cds_config:
    path: value2
  ads_config:
    path: value3
headerPrefix: header_prefix_value
fatalActions:
- config: action1
- config: action2
defaultSocketInterface: new_socket_value
`))
}

func TestMergeMapIntfs_ResourcesCaseConflict(t *testing.T) {
	setup()
	var b map[string]interface{}
	data := []byte(`
dynamic_resources:
  lds_config:
    path: value1
dynamicResources:
  cds_config:
    path: value2
`)
	err := yaml.Unmarshal(data, &b)
	if err != nil {
		t.Error(err)
	}
	bb := make(map[string]interface{})
	// All the keys in data2 should already be normalized to lowerCamelCase since as it is the destination and
	// any value merged to the destination so far will have the key in lowerCamelCase.
	data2 := []byte(`
staticResources:
  clusters: []
  listeners: []
  secrets: []
`)
	err = yaml.Unmarshal(data2, &bb)
	if err != nil {
		t.Error(err)
	}
	// All resources are replaced, so old values get overwritten.
	bootConfig, err := mergeDstMapInterfaceWithSrc(bb, b)
	assertError(t, bootConfig, err)

}

func TestNormalizeMapKeysToCamelCase(t *testing.T) {
	setup()
	var b map[string]interface{}
	data := []byte(`
static_resources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	err := yaml.Unmarshal(data, &b)
	if err != nil {
		t.Error(err)
	}
	b, err = normalizeMapKeyToCamelCase(b, "staticResources")
	if err != nil {
		t.Error(err)
	}
	output, err := yaml.Marshal(b)
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, output, []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`))

	// If key is a single word expect no change in map
	var bb map[string]interface{}
	tdata := []byte(`
tracing:
  http:
    name: envoy.tracers.xray
`)
	err = yaml.Unmarshal(tdata, &bb)
	if err != nil {
		t.Error(err)
	}
	bb, err = normalizeMapKeyToCamelCase(bb, "tracing")
	output, err = yaml.Marshal(bb)
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, output, []byte(`
tracing:
  http:
    name: envoy.tracers.xray
`))
}

func TestAppendConfigFromFile_Tracing(t *testing.T) {
	setup()
	data := []byte(`
tracing:
  http:
    name: envoy.tracers.zipkin
    typedConfig:
      '@type': type.googleapis.com/envoy.config.trace.v3.ZipkinConfig
      collectorCluster: jaeger
      collectorEndpoint: /api/v2/spans
      collectorEndpointVersion: HTTP_PROTO
      sharedSpanContext: false
staticResources:
  clusters:
  - connectTimeout: 1s
    loadAssignment:
      clusterName: jaeger
      endpoints:
      - lbEndpoints:
        - endpoint:
            address:
              socketAddress:
                address: 127.0.0.1
                portValue: 9411
    name: jaeger
    type: STRICT_DNS
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_TRACING_CFG_FILE", "/dev/null")
	var bootYaml []byte
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, bootYaml, data)
}

func TestAppendConfigFromFile_TracingEmpty(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_TRACING_CFG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	// mocking FileUtil doesn't return error when file is empty , but still expect error after parsing.
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil([]byte{}, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_TracingConflict(t *testing.T) {
	setup()
	data := []byte(`
tracing:
  http:
    name: envoy.tracers.zipkin
    typedConfig:
      '@type': type.googleapis.com/envoy.config.trace.v3.ZipkinConfig
      collectorCluster: jaeger
      collectorEndpoint: /api/v2/spans
      collectorEndpointVersion: HTTP_PROTO
      sharedSpanContext: false
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_TRACING_CFG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
tracing:
  http:
    name: envoy.tracers.xray
    typedConfig:
      '@type': type.googleapis.com/envoy.config.trace.v3.XRayConfig
      daemonEndpoint:
        address: 127.0.0.1
        portValue: 2000
        protocol: UDP
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_TracingNoFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_TRACING_CFG_FILE", "/dev/null")
	bootYaml, err := mergeCustomConfigs([]byte{}, newMockFileUtil([]byte{}, fmt.Errorf("file not present")))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_Stats(t *testing.T) {
	setup()
	data := []byte(`
stats_config:
  statsTags:
  - fixedValue: MicroserviceMesh
    tagName: appmesh.mesh
  - fixedValue: resourceName
    tagName: appmesh.resource_type
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_CONFIG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, bootYaml, []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
statsConfig:
  statsTags:
  - fixedValue: MicroserviceMesh
    tagName: appmesh.mesh
  - fixedValue: resourceName
    tagName: appmesh.resource_type
`))
}

func TestAppendConfigFromFile_StatsEmpty(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_CONFIG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	// mocking FileUtil doesn't return error when file is empty , but still expect error after parsing.
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil([]byte{}, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_StatsConflict(t *testing.T) {
	setup()
	data := []byte(`
stats_config:
  statsTags:
  - fixedValue: MicroserviceMesh
    tagName: appmesh.mesh
  - fixedValue: resourceName
    tagName: appmesh.resource_type
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_CONFIG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
statsConfig:
  statsTags:
  - fixedValue: MicroserviceMesh
    tagName: appmesh.mesh
  - fixedValue: resourceName
    tagName: appmesh.resource_type
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_StatsConflictWithCase(t *testing.T) {
	setup()
	data := []byte(`
stats_config:
  statsTags:
  - fixedValue: MicroserviceMesh
    tagName: appmesh.mesh
  - fixedValue: resourceName
    tagName: appmesh.resource_type
statsConfig:
  statsTags:
  - fixedValue: MicroserviceMesh
    tagName: appmesh.mesh
  - fixedValue: resourceName
    tagName: appmesh.resource_type
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_CONFIG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_StatsNoFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_CONFIG_FILE", "/dev/null")
	bootYaml, err := mergeCustomConfigs([]byte{}, newMockFileUtil([]byte{}, fmt.Errorf("file not present")))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_StatsSinks(t *testing.T) {
	setup()
	data := []byte(`
statsSinks:
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8125
        protocol: UDP
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_SINKS_CFG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, bootYaml, []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
statsSinks:
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8125
        protocol: UDP
`))
}

func TestAppendConfigFromFile_StatsSinksEmpty(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_SINKS_CFG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	// mocking FileUtil doesn't return error when file is empty , but still expect error after parsing.
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil([]byte{}, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_StatsSinksRepeat(t *testing.T) {
	setup()
	data := []byte(`
stats_sinks:
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8126
        protocol: UDP
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_SINKS_CFG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
statsSinks:
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8125
        protocol: UDP
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, bootYaml, []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
statsSinks:
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8125
        protocol: UDP
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8126
        protocol: UDP
`))
}

func TestAppendConfigFromFile_StatsSinksConflictWithCase(t *testing.T) {
	setup()
	data := []byte(`
stats_sinks:
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8126
        protocol: UDP
statsSinks:
- name: envoy.stat_sinks.dog_statsd
  typedConfig:
    '@type': type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink
    address:
      socketAddress:
        address: 127.0.0.1
        portValue: 8125
        protocol: UDP
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_SINKS_CFG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_StatsSinksNoFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_STATS_SINKS_CFG_FILE", "/dev/null")
	bootYaml, err := mergeCustomConfigs([]byte{}, newMockFileUtil([]byte{}, fmt.Errorf("file not present")))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_Resources(t *testing.T) {
	setup()
	data := []byte(`
static_resources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
dynamic_resources:
  lds_config:
    path: value1
  cds_config:
    path: value2
  ads_config:
    path: value3
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_RESOURCES_CONFIG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
dynamicResources:
  lds_config: existing_value
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, bootYaml, []byte(`
staticResources:
  clusters:
    - a: value
    - a: value
  listeners:
    - b: value
    - b: value
  secrets:
    - c: value
    - c: value
dynamicResources:
  lds_config:
    path: value1
  cds_config:
    path: value2
  ads_config:
    path: value3
`))
}

func TestAppendConfigFromFile_ResourcesEmpty(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_RESOURCES_CONFIG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`)
	// mocking FileUtil doesn't return error when file is empty & we ignore this for ENVOY_RESOURCES_CONFIG_FILE.
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil([]byte{}, nil))
	if err != nil {
		t.Error(err)
	}
	compareYaml(t, bootYaml, []byte(`
staticResources:
  clusters:
    - a: value
  listeners:
    - b: value
  secrets:
    - c: value
`))
}

func TestAppendConfigFromFile_ResourcesCaseConflict(t *testing.T) {
	setup()
	data := []byte(`
static_resources:
  clusters:
    - a: value
staticResources:
  clusters:
    - a: value
`)
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_RESOURCES_CONFIG_FILE", "/dev/null")
	bootYaml := []byte(`
staticResources:
  clusters:
    - a: value
`)
	bootYaml, err := mergeCustomConfigs(bootYaml, newMockFileUtil(data, nil))
	assertError(t, bootYaml, err)
}

func TestAppendConfigFromFile_ResourcesNoFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("ENVOY_RESOURCES_CONFIG_FILE", "/dev/null")
	bootYaml, err := mergeCustomConfigs([]byte{}, newMockFileUtil([]byte{}, fmt.Errorf("file not present")))
	assertError(t, bootYaml, err)
}

func TestCreateBootstrapYamlFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	defer os.Unsetenv("AWS_REGION")
	defer os.Unsetenv("APPMESH_RESOURCE_ARN")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	CreateBootstrapYamlFile(agentConfig)
	statInfo, err := os.Lstat(agentConfig.EnvoyConfigPath)
	assert.Nil(t, err)
	assert.NotEqual(t, statInfo.Size(), 0)
}

func TestCreateBootstrapYamlFileForRelayEndpoint(t *testing.T) {
	setup()
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	defer os.Unsetenv("APPMESH_RESOURCE_ARN")
	os.Setenv("APPMESH_XDS_ENDPOINT", "unix:///tmp/xds-envoy-test.sock")
	defer os.Unsetenv("APPMESH_XDS_ENDPOINT")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	CreateBootstrapYamlFile(agentConfig)
	statInfo, err := os.Lstat(agentConfig.EnvoyConfigPath)
	assert.Nil(t, err)
	assert.NotEqual(t, statInfo.Size(), 0)
}

func TestRelayBootstrap_NullConfigFile(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "1")
	defer os.Unsetenv("AWS_REGION")
	defer os.Unsetenv("APPMESH_RESOURCE_ARN")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	b, err := GetRelayBootstrapYaml(agentConfig, mockFileUtil)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, b, []byte{})
}

func TestRelayBootstrap_DefaultValuesSetForEnvVariables(t *testing.T) {
	setup()
	os.Setenv("AWS_REGION", "us-west-2")
	os.Setenv("APPMESH_RESOURCE_ARN", "mesh/foo/virtualNode/bar")
	os.Setenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS", "1")
	defer os.Unsetenv("AWS_REGION")
	defer os.Unsetenv("APPMESH_RESOURCE_ARN")
	defer os.Unsetenv("APPNET_ENABLE_RELAY_MODE_FOR_XDS")
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	mockFileUtil := newMockFileUtil([]byte{}, nil)
	_, e := GetRelayBootstrapYaml(agentConfig, mockFileUtil)
	assert.Nil(t, e)

	_, a_exists := os.LookupEnv("APPNET_RELAY_LISTENER_UDS_PATH")
	assert.True(t, a_exists)

	_, b_exists := os.LookupEnv("AWS_REGION")
	assert.True(t, b_exists)

	_, c_exists := os.LookupEnv("APPNET_MANAGEMENT_DOMAIN_NAME")
	assert.True(t, c_exists)

	_, d_exists := os.LookupEnv("APPNET_MANAGEMENT_PORT")
	assert.True(t, d_exists)

	_, e_exists := os.LookupEnv("RELAY_STREAM_IDLE_TIMEOUT")
	assert.True(t, e_exists)

	_, f_exists := os.LookupEnv("RELAY_BUFFER_LIMIT_BYTES")
	assert.True(t, f_exists)
}
