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

package listenerinfo

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
	os.Setenv("APPNET_LISTENER_PORT_MAPPING", `{"Listener1":15000,"Listener2":15001"}`)
	defer os.Unsetenv("APPNET_LISTENER_PORT_MAPPING")
	metadata, err := BuildMetadata()

	assert.NotNil(t, err)
	assert.Nil(t, metadata)
}

func TestInvalidEnvVar_NotMap(t *testing.T) {
	setup()
	os.Setenv("APPNET_LISTENER_PORT_MAPPING", `[{"Listener1":15000,"Listener2":15001}]`)
	defer os.Unsetenv("APPNET_LISTENER_PORT_MAPPING")
	metadata, err := BuildMetadata()

	assert.NotNil(t, err)
	assert.Nil(t, metadata)
}

func TestValidEnvVar(t *testing.T) {
	setup()
	os.Setenv("APPNET_LISTENER_PORT_MAPPING", `{"Listener1":15000,"Listener2":15001}`)
	defer os.Unsetenv("APPNET_LISTENER_PORT_MAPPING")
	metadata, err := BuildMetadata()

	assert.Nil(t, err)
	assert.NotNil(t, metadata)
	listenerPortMapping := metadata["aws.ecs.serviceconnect.ListenerPortMapping"].(map[string]interface{})
	assert.Equal(t, 2, len(listenerPortMapping))
	assert.Equal(t, int((listenerPortMapping["Listener1"]).(float64)), 15000)
	assert.Equal(t, int((listenerPortMapping["Listener2"]).(float64)), 15001)
}
