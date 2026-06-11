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

package servicediscovery

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testNamespaceName = "test-namespace"
	testNamespaceArn  = "arn:aws:servicediscovery:us-west-2:123456789012:namespace/ns-12345"
)

func setup() {
	os.Clearenv()
}

func TestBuildMetadata(t *testing.T) {
	tests := []struct {
		name                 string
		setEnvVars           map[string]string // env vars to set; absent key = unset
		expectedKeys         map[string]string // expected metadata keys; absent key = should not appear
		setMetadataNamespace bool              // whether the top-level ServiceDiscovery namespace is emitted
	}{
		{
			name: "both set",
			setEnvVars: map[string]string{
				namespaceNameEnvVar: testNamespaceName,
				namespaceArnEnvVar:  testNamespaceArn,
			},
			expectedKeys: map[string]string{
				namespaceNameKey: testNamespaceName,
				namespaceArnKey:  testNamespaceArn,
			},
			setMetadataNamespace: true,
		},
		{
			name:                 "only name set",
			setEnvVars:           map[string]string{namespaceNameEnvVar: testNamespaceName},
			expectedKeys:         map[string]string{namespaceNameKey: testNamespaceName},
			setMetadataNamespace: true,
		},
		{
			name: "name set, arn empty",
			setEnvVars: map[string]string{
				namespaceNameEnvVar: testNamespaceName,
				namespaceArnEnvVar:  "",
			},
			expectedKeys:         map[string]string{namespaceNameKey: testNamespaceName},
			setMetadataNamespace: true,
		},
		{
			name:                 "only arn set",
			setEnvVars:           map[string]string{namespaceArnEnvVar: testNamespaceArn},
			expectedKeys:         map[string]string{namespaceArnKey: testNamespaceArn},
			setMetadataNamespace: true,
		},
		{
			name: "name empty, arn set",
			setEnvVars: map[string]string{
				namespaceNameEnvVar: "",
				namespaceArnEnvVar:  testNamespaceArn,
			},
			expectedKeys:         map[string]string{namespaceArnKey: testNamespaceArn},
			setMetadataNamespace: true,
		},
		{
			name:                 "both unset",
			setMetadataNamespace: false,
		},
		{
			name:                 "name unset, arn empty",
			setEnvVars:           map[string]string{namespaceArnEnvVar: ""},
			setMetadataNamespace: false,
		},
		{
			name:                 "name empty, arn unset",
			setEnvVars:           map[string]string{namespaceNameEnvVar: ""},
			setMetadataNamespace: false,
		},
		{
			name: "both empty",
			setEnvVars: map[string]string{
				namespaceNameEnvVar: "",
				namespaceArnEnvVar:  "",
			},
			setMetadataNamespace: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup()
			for k, v := range tc.setEnvVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			metadata, err := BuildMetadata()
			assert.Nil(t, err)

			mapping, ok := metadata[metadataNamespace].(map[string]interface{})
			assert.Equal(t, tc.setMetadataNamespace, ok)
			if !tc.setMetadataNamespace {
				return
			}

			for key, expectedValue := range tc.expectedKeys {
				assert.Equal(t, expectedValue, mapping[key], "key %q", key)
			}
			assert.Equal(t, len(tc.expectedKeys), len(mapping),
				"unexpected extra keys in mapping: %v", mapping)
		})
	}
}
