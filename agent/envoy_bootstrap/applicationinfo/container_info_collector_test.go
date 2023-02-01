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

package applicationinfo

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setup() {
	os.Clearenv()
}

func TestUndefinedEnvVar(t *testing.T) {
	setup()
	metadata, err := BuildMetadata()

	assert.Nil(t, err)
	assert.NotNil(t, metadata)
	assert.Equal(t, 0, len(metadata))
}

func TestInvalidEnvVar(t *testing.T) {
	setup()
	os.Setenv("APPNET_CONTAINER_IP_MAPPING", `{"C1":"172.10.1.1","C2":"172.10.1.2}`)
	defer os.Unsetenv("APPNET_CONTAINER_IP_MAPPING")
	metadata, err := BuildMetadata()

	assert.NotNil(t, err)
	assert.Nil(t, metadata)
}

func TestValidEnvVar(t *testing.T) {
	setup()
	os.Setenv("APPNET_CONTAINER_IP_MAPPING", `{"C1":"172.10.1.1","C2":"172.10.1.2"}`)
	defer os.Unsetenv("APPNET_CONTAINER_IP_MAPPING")
	metadata, err := BuildMetadata()

	assert.Nil(t, err)
	assert.NotNil(t, metadata)
	containerIPMapping := metadata["aws.ecs.serviceconnect.ClusterIPMapping"].(map[string]interface{})
	assert.Equal(t, 2, len(containerIPMapping))
	assert.Equal(t, containerIPMapping["C1"], "172.10.1.1")
	assert.Equal(t, containerIPMapping["C2"], "172.10.1.2")
}
