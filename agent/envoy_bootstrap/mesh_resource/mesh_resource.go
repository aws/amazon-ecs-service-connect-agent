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

package mesh_resource

type MeshResource struct {
	MeshName string
	// The resource type in lowerCamelCase. ex: virtualNode
	Type string
	// The resource type in UpperCamelCase. ex: virtualNode => VirtualNode
	UpperCamelCaseType string
	// The resource type in snake_case. ex: virtualNode => virtual_node
	SnakeCaseType string
	Name          string
}
