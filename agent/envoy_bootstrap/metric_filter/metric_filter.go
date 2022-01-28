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
	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/env"
	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/mesh_resource"

	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
)

const (
	extensionVersionEnvVar = "APPMESH_METRIC_EXTENSION_VERSION"
	metadataNamespace      = "aws.appmesh.metric_filter"
	metricFilterLevelKey   = "level"

	targetVirtualNodeRegex = "^appmesh(?:\\..+?\\..+?)*(\\.TargetVirtualNode\\.(.+?))(?:\\..+?\\..+?)*\\.(?:.+)$"
	// Virtual Service Names can contain "." unfortunately, so we must greedily match anything that doesnt start with M|V|T (prefix of known tag names)
	// TODO: We could add a sort key / tag priority field in our filter to ensure this tag is always the last
	targetVirtualServiceRegex = "^appmesh(?:\\..+?\\..+?)*(\\.TargetVirtualService\\.([^MVT]+))(?:\\..+?\\..+?)*\\.(?:.+)$"
)

func extensionVersion() string {
	return env.Or(extensionVersionEnvVar, "0")
}

func AppendStatsTagRegex(tags *[]*metrics.TagSpecifier, res *mesh_resource.MeshResource) error {
	if extensionVersion() != "1" {
		return nil
	}
	*tags = append(*tags, &metrics.TagSpecifier{
		TagName: "TargetVirtualNode",
		TagValue: &metrics.TagSpecifier_Regex{
			Regex: targetVirtualNodeRegex,
		},
	})

	// NOTE: TargetVirtualService *must* be the last regex match since it greedily matches.
	// Virtual service names contain '.' which is also used as a metric namespace delimiter in Envoy
	*tags = append(*tags, &metrics.TagSpecifier{
		TagName: "TargetVirtualService",
		TagValue: &metrics.TagSpecifier_Regex{
			Regex: targetVirtualServiceRegex,
		},
	})

	*tags = append(*tags, &metrics.TagSpecifier{
		TagName: "Mesh",
		TagValue: &metrics.TagSpecifier_FixedValue{
			FixedValue: res.MeshName,
		},
	})
	*tags = append(*tags, &metrics.TagSpecifier{
		TagName: res.UpperCamelCaseType,
		TagValue: &metrics.TagSpecifier_FixedValue{
			FixedValue: res.Name,
		},
	})

	return nil
}

func BuildMetadata() (*map[string]interface{}, error) {
	level := extensionVersion()
	md := make(map[string]interface{})

	// For now, just accept a value of "1". This is not a true/false value
	// but rather opting into a level-of-detail.
	// Future additions to the filters will require opting into higher
	// levels.
	if level == "1" {
		md[metadataNamespace] = map[string]interface{}{
			metricFilterLevelKey: level,
		}
	}
	return &md, nil
}
