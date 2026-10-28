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
	// Stat names look like "appmesh.<key>.<value>...<key>.<value>.<metric>". Values can contain "."
	// (e.g. NamespaceName), so a value runs until the next ".<known key>." or the
	// last segment, which is the metric name. Since a value always ends at the next known key, a name
	// can only be split into key/value pairs one way.
	//
	// Envoy runs every specifier on the original name and strips the matched tags only after all of
	// them have run, so each regex still sees the other tags. Every key that can appear in a stat
	// name must be listed in scTagKeys. An unlisted key and its value end up inside the previous
	// tag's value.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/metrics/v3/stats.proto#envoy-v3-api-msg-config-metrics-v3-tagspecifier
	scTagKeys = "(?:ClusterName|ServiceName|Direction|" +
		"DiscoveryName|TargetDiscoveryName|" +
		"AvailabilityZoneId|TargetAvailabilityZoneId|" +
		"NamespaceName)"
	scTagValue  = "(?:(?!\\." + scTagKeys + "\\.).)+"
	scTagPair   = "\\." + scTagKeys + "\\." + scTagValue
	scTagPrefix = "^appmesh(?:" + scTagPair + ")*?"
	scTagSuffix = "(?:\\..*)?\\.[^.]+$"

	serviceNameRegex              = scTagPrefix + "(\\.ServiceName\\.(" + scTagValue + "))" + scTagSuffix
	clusterNameRegex              = scTagPrefix + "(\\.ClusterName\\.(" + scTagValue + "))" + scTagSuffix
	directionRegex                = scTagPrefix + "(\\.Direction\\.(" + scTagValue + "))" + scTagSuffix
	discoveryNameRegex            = scTagPrefix + "(\\.DiscoveryName\\.(" + scTagValue + "))" + scTagSuffix
	targetDiscoveryNameRegex      = scTagPrefix + "(\\.TargetDiscoveryName\\.(" + scTagValue + "))" + scTagSuffix
	namespaceNameRegex            = scTagPrefix + "(\\.NamespaceName\\.(" + scTagValue + "))" + scTagSuffix
	availabilityZoneIdRegex       = scTagPrefix + "(\\.AvailabilityZoneId\\.(" + scTagValue + "))" + scTagSuffix
	targetAvailabilityZoneIdRegex = scTagPrefix + "(\\.TargetAvailabilityZoneId\\.(" + scTagValue + "))" + scTagSuffix
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
			TagName: "DiscoveryName",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: discoveryNameRegex,
			},
		}, {
			TagName: "TargetDiscoveryName",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: targetDiscoveryNameRegex,
			},
		}, {
			TagName: "NamespaceName",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: namespaceNameRegex,
			},
		}, {
			TagName: "AvailabilityZoneId",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: availabilityZoneIdRegex,
			},
		}, {
			TagName: "TargetAvailabilityZoneId",
			TagValue: &metrics.TagSpecifier_Regex{
				Regex: targetAvailabilityZoneIdRegex,
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
