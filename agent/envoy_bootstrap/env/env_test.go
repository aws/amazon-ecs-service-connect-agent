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

package env

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setup() {
	os.Clearenv()
}

func TestEnv_Defined(t *testing.T) {
	setup()
	os.Setenv("EXAMPLE", "1\n1")
	v := Get("EXAMPLE")
	assert.Equal(t, "1\n1", v)
}

func TestEnv_DefinedEmptySpace(t *testing.T) {
	setup()
	os.Setenv("EXAMPLE", " \n\t ")
	v := Get("EXAMPLE")
	assert.Equal(t, "", v)
}

func TestEnv_NotDefined(t *testing.T) {
	setup()
	v := Get("EXAMPLE")
	assert.Equal(t, "", v)
}

func TestEnvOr_Defined(t *testing.T) {
	setup()
	os.Setenv("EXAMPLE", "1")
	v := Or("EXAMPLE", "0")
	assert.Equal(t, "1", v)
}

func TestEnvOr_NotDefined(t *testing.T) {
	setup()
	v := Or("EXAMPLE", "2")
	assert.Equal(t, "2", v)
}

func TestEnvOrInt_NotDefined(t *testing.T) {
	setup()
	i, err := OrInt("EXAMPLE", 3)
	assert.Nil(t, err)
	assert.Equal(t, 3, i)
}

func TestEnvOrInt_Defined_NotInt(t *testing.T) {
	setup()
	os.Setenv("EXAMPLE", "foo")
	_, err := OrInt("EXAMPLE", 0)
	assert.Error(t, err)
}

func TestEnvOrInt_Defined(t *testing.T) {
	setup()
	os.Setenv("EXAMPLE", "4")
	i, err := OrInt("EXAMPLE", 0)
	assert.Nil(t, err)
	assert.Equal(t, 4, i)
}

func TestEnvTruthy_Defined(t *testing.T) {
	setup()
	os.Setenv("EXAMPLE", "true")
	b, err := Truthy("EXAMPLE")
	assert.Nil(t, err)
	assert.True(t, b)
}

func TestEnvTruthy_NotDefined(t *testing.T) {
	setup()
	b, err := Truthy("EXAMPLE")
	assert.Nil(t, err)
	assert.False(t, b)
}

func TestEnvTruthy_Malformed(t *testing.T) {
	setup()
	os.Setenv("EXAMPLE", "2")
	_, err := Truthy("EXAMPLE")
	assert.Error(t, err)
}
