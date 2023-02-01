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
)

const (
	// TagSpecifier Regex for Service Connect
	clusterNameRegex = "^appmesh(?:\\..+?\\..+?)*(\\.ClusterName\\.(.+?))(?:\\..+?\\..+?)*\\.(?:.+)$"
	directionRegex   = "^appmesh(?:\\..+?\\..+?)*(\\.Direction\\.(.+?))(?:\\..+?\\..+?)*\\.(?:.+)$"
	// Note that DiscoveryName and TargetDiscoveryName can contain "." unfortunately, so we aggressively match any
	// character after ".".
	//
	// According to the official doc (https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/metrics/v3/stats.proto#envoy-v3-api-msg-config-metrics-v3-tagspecifier), only after all tag specifiers are processed the tags will be removed from the name.
	// For any intermediate tag specifier matching, it will leave it in the name for potential matching with additional tag specifiers.
	// So we have to explicitly exclude other tag keywords in the regex for DiscoveryName and TargetDiscoveryName.
	discoveryNameRegex       = "^appmesh(?:\\..+?\\..+?)*(\\.DiscoveryName\\.((?:(?!\\.(ClusterName|ServiceName|Direction)).)+))(?:\\..+?\\..+?)*\\.(?:.+)$"
	serviceNameRegex         = "^appmesh(?:\\..+?\\..+?)*(\\.ServiceName\\.(.+?))(?:\\..+?\\..+?)*\\.(?:.+)$"
	targetDiscoveryNameRegex = "^appmesh(?:\\..+?\\..+?)*(\\.TargetDiscoveryName\\.((?:(?!\\.(ClusterName|ServiceName|Direction)).)+))(?:\\..+?\\..+?)*\\.(?:.+)$"
)

const (
	// TagSpecifier Regex for AppMesh
	targetVirtualNodeRegex = "^appmesh(?:\\..+?\\..+?)*(\\.TargetVirtualNode\\.(.+?))(?:\\..+?\\..+?)*\\.(?:.+)$"
	// Virtual Service Names can contain "." unfortunately, so we must greedily match anything that doesnt start with M|V|T (prefix of known tag names)
	// TODO: We could add a sort key / tag priority field in our filter to ensure this tag is always the last
	targetVirtualServiceRegex = "^appmesh(?:\\..+?\\..+?)*(\\.TargetVirtualService\\.([^MVT]+))(?:\\..+?\\..+?)*\\.(?:.+)$"
)

func extensionVersion() string {
	return env.Or(extensionVersionEnvVar, "0")
}

func AppendStatsTagRegexForAppMesh(tags *[]*metrics.TagSpecifier, res *mesh_resource.MeshResource) {
	if extensionVersion() != "1" {
		return
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
}

func AppendStatsTagRegexForServiceConnect(tags *[]*metrics.TagSpecifier) {
	if extensionVersion() != "1" {
		return
	}
	serviceConnectTags := []*metrics.TagSpecifier{
		{
			TagName: "ServiceName",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: serviceNameRegex,
			},
		}, {
			TagName: "ClusterName",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: clusterNameRegex,
			},
		}, {
			TagName: "Direction",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: directionRegex,
			},
		}, {
			// We ensure that DiscoveryName and TargetDiscoveryName are matched at last.
			TagName: "DiscoveryName",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: discoveryNameRegex,
			},
		}, {
			TagName: "TargetDiscoveryName",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: targetDiscoveryNameRegex,
			},
		},
	}
	*tags = append(*tags, serviceConnectTags...)
}

func BuildMetadata() (*map[string]interface{}, error) {
	level := extensionVersion()
	metadata := make(map[string]interface{})

	// For now, just accept a value of "1". This is not a true/false value
	// but rather opting into a level-of-detail.
	// Future additions to the filters will require opting into higher
	// levels.
	if level == "1" {
		metadata[metadataNamespace] = map[string]interface{}{
			metricFilterLevelKey: level,
		}
	}
	return &metadata, nil
}
