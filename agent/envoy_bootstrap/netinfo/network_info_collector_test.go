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

package netinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsIpv4(t *testing.T) {
	addresses := []string{
		"192.168.1.1",
		"8.8.8.8/32",
		"127.0.0.1/8",
	}

	for address := range addresses {
		assert.True(t, isIpv4(addresses[address]))
	}
}

func TestIsInvalidIpv4(t *testing.T) {
	addresses := []string{
		"192.168.1.1/123",
		"8.8.8/32",
	}

	for address := range addresses {
		assert.False(t, isIpv4(addresses[address]))
	}
}

func TestIsIpv6(t *testing.T) {
	addresses := []string{
		"::1",
		"::1/128",
		"2001:570:eb51:223:70b0:b1df:a70e:3c5f",
		"2001:570:eb51:223:70b0:b1df:a70e:3c5f/64",
	}

	for address := range addresses {
		assert.True(t, isIpv6(addresses[address]))
	}
}

func TestIsInvalidIpv6(t *testing.T) {
	addresses := []string{
		":::1",
		"::1/129",
		"2001:eb51:223:70b0:b1df:a70e:3c5f/64",
		":::223:70b0:b1df:a70e:3c5f/64",
	}

	for address := range addresses {
		assert.False(t, isIpv6(addresses[address]))
	}
}

func verifyInterfaces(
	t *testing.T,
	interfaceAddrMap map[string]interface{},
	interfaceCount int,
	addressCount int) {

	assert.GreaterOrEqual(t, len(interfaceAddrMap), interfaceCount)

	// We don't care what the interface names are here, just validate
	// that for each interface we have at least the addressCount addresses
	for _, addresses := range interfaceAddrMap {
		assert.GreaterOrEqual(t, len(addresses.([]interface{})), addressCount)
	}
}

func TestMapConstruction(t *testing.T) {
	metadata, err := BuildMapWithInterfaceInfo()
	assert.Nil(t, err)
	assert.NotNil(t, metadata)

	addressTypes, exists := (*metadata)[namespace]
	assert.True(t, exists)

	// Verify only ipv4 since it's not guaranteed that
	// 1. ipv6 is enabled everywhere we build this
	// 2. interface names may change so we should have at least two
	//    interfaces (lo and the network connected interface) and
	//    one address per interface for ipv4

	ipTypes := addressTypes.(map[string]interface{})
	assert.GreaterOrEqual(t, len(ipTypes), 1)

	for k, interfaceAddrMap := range ipTypes {
		switch k {
		case ipv4:
			verifyInterfaces(t, interfaceAddrMap.(map[string]interface{}), 2, 1)
		case ipv6:
			// Optional case.
			// If we do have interfaces, they should have at least 1 address
			verifyInterfaces(t, interfaceAddrMap.(map[string]interface{}), 0, 1)
		}
	}

}
