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
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	ipv4 = "ipv4"
	ipv6 = "ipv6"

	namespace = "aws.appmesh.task.interfaces"
)

// TODO: Since this interracts with real network interfaces we need to make
//  an interface for this struct that we can mock it during UTs.

// InterfaceAddressMap holds a mapping of interface name to its addresses for a
// single IP version
// eg: "eth0" : [ "1.1.1.1", "2.2.2.2" ] is what's stored here
type interfaceAddressMap map[string][]string

// private function to add a new address to an interface
func addAddressToMap(addressMap interfaceAddressMap, interfaceName string, address string) {
	if _, exists := addressMap[interfaceName]; !exists {
		addressMap[interfaceName] = []string{address}
	} else {
		addressMap[interfaceName] = append(addressMap[interfaceName], address)
	}
}

// AddressTypeMap holds a mapping of IP version to the interface and list of addresses
// corresponding to that IP Version
// eg: "ipv4" : { "eth0": [ "1.1.1.1", "2.2.2.2"] } }" is what this will look like
type addressTypeMap struct {
	interfaceMapping map[string]interfaceAddressMap
}

func (addrTypeMap *addressTypeMap) addInterfaceAddress(
	interfaceName string,
	addrType string,
	address string) {

	// The TypeMap should have 2 keys. ipv4/ipv6.
	// In each bucket, we will have the interface name and a list of addresses of that type.
	if addressMap, exists := addrTypeMap.interfaceMapping[addrType]; !exists {
		var addressMap interfaceAddressMap = make(interfaceAddressMap)
		addAddressToMap(addressMap, interfaceName, address)

		if addrTypeMap.interfaceMapping == nil {
			addrTypeMap.interfaceMapping = make(map[string]interfaceAddressMap)
		}

		addrTypeMap.interfaceMapping[addrType] = addressMap
		log.WithFields(log.Fields{
			"addressMap":   addressMap,
			"address":      address,
			"intefaceName": interfaceName,
		}).Debug("Adding new addressMap for interface")
	} else {
		addAddressToMap(addressMap, interfaceName, address)
		log.WithFields(log.Fields{
			"addressMap":   addressMap,
			"address":      address,
			"intefaceName": interfaceName,
		}).Debug("Updating existing addressMap for interface")
	}
}

// If there is a CIDR part of the address, validate the value
func isValidCidr(parts []string, cidrValue int) bool {
	if len(parts) > 1 {
		cidr, err := strconv.Atoi(parts[1])
		if err != nil || cidr > cidrValue {
			return false
		}
	}
	return true
}

// IsIpv4 indicates whether the address spring is an IPv4 Address
func isIpv4(address string) bool {
	parts := strings.Split(address, "/")
	if !isValidCidr(parts, 32) {
		return false
	}
	ip := net.ParseIP(parts[0])
	return ip.To4() != nil
}

// IsIpv6 indicates whether the address string is an IPv6 address
func isIpv6(address string) bool {
	parts := strings.Split(address, "/")
	if !isValidCidr(parts, 128) {
		return false
	}
	ip := net.ParseIP(parts[0])
	return ip.To16() != nil
}

// Build a map of the interface addresses grouped by IP version and interface name
func getInterfaceAddressInfo(iface net.Interface, addressTypeMap *addressTypeMap) error {
	addressData, err := iface.Addrs()

	if err != nil {
		log.WithFields(log.Fields{
			"interface": iface.Name,
		}).Error("Unable to obtain addresses for interface")
		return err
	}

	log.WithFields(log.Fields{
		"interface":   iface.Name,
		"addressData": addressData,
	}).Debug("using addressData for interface")

	for index := range addressData {
		address := addressData[index].String()

		var key string
		if isIpv4(address) {
			key = ipv4
		} else if isIpv6(address) {
			key = ipv6
		} else {
			continue
		}

		addressTypeMap.addInterfaceAddress(iface.Name, key, address)
	}

	return nil
}

// BuildMapWithInterfaceInfo generates a map containing the interfaces
// on the system grouped by IP Version then interface name
func BuildMapWithInterfaceInfo() (*map[string]interface{}, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Error("Unable to get network interfaces on host")
		return nil, err
	}

	var addressMap addressTypeMap

	for index := range ifaces {
		iface := ifaces[index]
		log.WithFields(log.Fields{
			"interface": iface.Name,
		}).Debug("Loading addresses for interface")

		err := getInterfaceAddressInfo(iface, &addressMap)
		if err != nil {
			log.WithFields(log.Fields{
				"interface": iface.Name,
			}).Error("Unable to get address information for interface")
			continue
		}
	}

	log.WithFields(log.Fields{
		"addressMap": addressMap,
	}).Debug("Generated addressMap")

	// TODO: Should either use the json encoding library to iteratively build a map of JSON values
	//   or iteratively construct the map[string]interface{}. These loops just convert
	//   the strongly typed interface mapping data into just maps and lists of interface{}
	//   which is what protobuf needs to make a struct.
	mapping := make(map[string]interface{})
	for ipver, iface := range addressMap.interfaceMapping {
		mapping[ipver] = make(map[string]interface{})
		for name, ips := range iface {
			// convert the ip list to []interface{}
			iplist := make([]interface{}, len(ips))
			for i, ip := range ips {
				iplist[i] = ip
			}
			mapping[ipver].(map[string]interface{})[name] = iplist
		}
	}

	metadata := map[string]interface{}{
		namespace: mapping,
	}
	return &metadata, nil
}
