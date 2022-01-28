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

package metric_filter

import (
	"os"
	"testing"

	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/mesh_resource"

	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	"github.com/stretchr/testify/assert"
)

func setup() {
	os.Clearenv()
}

func TestUndefinedEnvVar(t *testing.T) {
	setup()
	md, err := BuildMetadata()

	assert.Nil(t, err)
	assert.NotNil(t, md)
	assert.Equal(t, 0, len(*md))
}

func TestMetricFilterLevelZero(t *testing.T) {
	setup()
	os.Setenv("APPMESH_METRIC_EXTENSION_VERSION", "0")
	md, err := BuildMetadata()

	assert.Nil(t, err)
	assert.NotNil(t, md)
	assert.Equal(t, 0, len(*md))
}

func TestMetricFilterLevelOne(t *testing.T) {
	setup()
	os.Setenv("APPMESH_METRIC_EXTENSION_VERSION", "1")
	md, err := BuildMetadata()

	assert.Nil(t, err)
	assert.NotNil(t, md)
	assert.Equal(t, 1, len(*md))

	metricFilter := (*md)["aws.appmesh.metric_filter"].(map[string]interface{})
	assert.NotNil(t, metricFilter)
	assert.Equal(t, 1, len(metricFilter))

	level := metricFilter["level"]
	assert.NotNil(t, level)
	assert.Equal(t, "1", level)
}

func TestAppendStatsTags_UndefinedEnv(t *testing.T) {
	setup()
	res := mesh_resource.MeshResource{
		MeshName:           "mesh-name",
		Type:               "virtualNode",
		UpperCamelCaseType: "VirtualNode",
		SnakeCaseType:      "virtual_node",
		Name:               "virtual-node-name",
	}
	tags := make([]*metrics.TagSpecifier, 0)
	AppendStatsTagRegex(&tags, &res)
	assert.Equal(t, 0, len(tags))
}

func TestAppendStatsTags_Level1(t *testing.T) {
	setup()
	os.Setenv("APPMESH_METRIC_EXTENSION_VERSION", "1")

	res := mesh_resource.MeshResource{
		MeshName:           "mesh-name",
		Type:               "virtualNode",
		UpperCamelCaseType: "VirtualNode",
		SnakeCaseType:      "virtual_node",
		Name:               "virtual-node-name",
	}

	tags := make([]*metrics.TagSpecifier, 0)
	AppendStatsTagRegex(&tags, &res)
	assert.Equal(t, 4, len(tags))

	assert.Equal(t, "TargetVirtualNode", tags[0].TagName)
	assert.Equal(t, targetVirtualNodeRegex, tags[0].GetRegex())

	assert.Equal(t, "TargetVirtualService", tags[1].TagName)
	assert.Equal(t, targetVirtualServiceRegex, tags[1].GetRegex())

	assert.Equal(t, "Mesh", tags[2].TagName)
	assert.Equal(t, "mesh-name", tags[2].GetFixedValue())

	assert.Equal(t, "VirtualNode", tags[3].TagName)
	assert.Equal(t, "virtual-node-name", tags[3].GetFixedValue())
}
