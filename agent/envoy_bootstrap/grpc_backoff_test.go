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

package bootstrap

import (
	"testing"
	"time"
)

func TestGrpcInitialReconnectBackoffSet_ConnectionFailure(t *testing.T) {
	setup()

	cfg, err := buildRegionalDynamicResources("endpoint", "region", "signing_name")
	if err != nil {
		t.Error(err)
	}

	grpcService := cfg.AdsConfig.GrpcServices[0]
	googleGrpc := grpcService.GetGoogleGrpc()

	if googleGrpc == nil {
		t.Error("Expected GoogleGrpc configuration to be present")
		return
	}

	channelArgs := googleGrpc.ChannelArgs
	if channelArgs == nil {
		t.Error("Expected ChannelArgs to be present")
		return
	}

	backoffArg, exists := channelArgs.Args["grpc.initial_reconnect_backoff_ms"]
	if !exists {
		t.Error("Expected grpc.initial_reconnect_backoff_ms to be set")
		return
	}

	backoffValue := backoffArg.GetIntValue()
	expectedBackoff := int64(GRPC_INITIAL_BACKOFF_MS) // 10000ms = 10 seconds

	if backoffValue != expectedBackoff {
		t.Errorf("Expected initial reconnect backoff to be %d ms, got %d ms", expectedBackoff, backoffValue)
	}

	backoffDuration := time.Duration(backoffValue) * time.Millisecond
	expectedDuration := 10 * time.Second

	if backoffDuration != expectedDuration {
		t.Errorf("Expected backoff duration to be %v, got %v", expectedDuration, backoffDuration)
	}
}

func TestGrpcInitialReconnectBackoffSet_RelayEndpoint(t *testing.T) {
	setup()

	cfg, err := buildDynamicResourcesForRelayEndpoint("unix:///tmp/xds-envoy-test.sock")
	if err != nil {
		t.Error(err)
	}

	grpcService := cfg.AdsConfig.GrpcServices[0]
	googleGrpc := grpcService.GetGoogleGrpc()

	if googleGrpc == nil {
		t.Error("Expected GoogleGrpc configuration to be present")
		return
	}

	channelArgs := googleGrpc.ChannelArgs
	if channelArgs == nil {
		t.Error("Expected ChannelArgs to be present")
		return
	}

	backoffArg, exists := channelArgs.Args["grpc.initial_reconnect_backoff_ms"]
	if !exists {
		t.Error("Expected grpc.initial_reconnect_backoff_ms to be set")
		return
	}

	backoffValue := backoffArg.GetIntValue()
	expectedBackoff := int64(GRPC_INITIAL_BACKOFF_MS) // 10000ms = 10 seconds

	if backoffValue != expectedBackoff {
		t.Errorf("Expected initial reconnect backoff to be %d ms, got %d ms", expectedBackoff, backoffValue)
	}
}

func TestGrpcBackoffBehavior_ConnectionFailureScenario(t *testing.T) {
	setup()

	// This test documents the expected behavior:
	// When a GRPC connection attempt fails, the next reconnection attempt
	// should happen after the initial reconnect backoff time (10 seconds)

	cfg, err := buildRegionalDynamicResources("endpoint", "region", "signing_name")
	if err != nil {
		t.Error(err)
	}

	grpcService := cfg.AdsConfig.GrpcServices[0]
	googleGrpc := grpcService.GetGoogleGrpc()
	channelArgs := googleGrpc.ChannelArgs

	expectedArgs := map[string]int64{
		"grpc.http2.max_pings_without_data": GRPC_MAX_PINGS_WITHOUT_DATA, // 0
		"grpc.keepalive_time_ms":            GRPC_KEEPALIVE_TIME_MS,      // 10000ms
		"grpc.keepalive_timeout_ms":         GRPC_KEEPALIVE_TIMEOUT_MS,   // 20000ms
		"grpc.initial_reconnect_backoff_ms": GRPC_INITIAL_BACKOFF_MS,     // 10000ms
	}

	for argName, expectedValue := range expectedArgs {
		arg, exists := channelArgs.Args[argName]
		if !exists {
			t.Errorf("Expected %s to be set", argName)
			continue
		}

		actualValue := arg.GetIntValue()
		if actualValue != expectedValue {
			t.Errorf("Expected %s to be %d, got %d", argName, expectedValue, actualValue)
		}
	}

	// Document the behavior:
	// - Connection failure -> wait 10 seconds (grpc.initial_reconnect_backoff_ms) -> retry
	// - Successful connection but server error -> connection is reset -> wait 10 seconds -> retry
	t.Logf("GRPC Backoff Behavior:")
	t.Logf("- Connection failure: Next attempt after %d ms (%v)",
		GRPC_INITIAL_BACKOFF_MS, time.Duration(GRPC_INITIAL_BACKOFF_MS)*time.Millisecond)
	t.Logf("- Server error after successful connection: Connection reset, next attempt after %d ms (%v)",
		GRPC_INITIAL_BACKOFF_MS, time.Duration(GRPC_INITIAL_BACKOFF_MS)*time.Millisecond)
}

func TestGrpcBackoffBehavior_ServerExceptionScenario(t *testing.T) {
	setup()

	// This test documents the expected behavior when:
	// 1. Connection succeeds initially
	// 2. Server throws an exception (not a connection error)
	// 3. Connection gets reset
	// 4. Next reconnection should use fixed 10-second backoff (no exponential growth)

	cfg, err := buildRegionalDynamicResources("endpoint", "region", "signing_name")
	if err != nil {
		t.Error(err)
	}

	grpcService := cfg.AdsConfig.GrpcServices[0]
	googleGrpc := grpcService.GetGoogleGrpc()
	channelArgs := googleGrpc.ChannelArgs

	maxBackoffArg, hasMaxBackoff := channelArgs.Args["grpc.max_reconnect_backoff_ms"]
	if !hasMaxBackoff {
		t.Error("Expected grpc.max_reconnect_backoff_ms to be set for fixed retry interval")
		return
	}

	maxBackoff := maxBackoffArg.GetIntValue()
	if maxBackoff != GRPC_MAX_BACKOFF_MS {
		t.Errorf("Expected max backoff to be %d ms, got %d ms", GRPC_MAX_BACKOFF_MS, maxBackoff)
	}

	initialBackoffArg, exists := channelArgs.Args["grpc.initial_reconnect_backoff_ms"]
	if !exists {
		t.Error("Expected grpc.initial_reconnect_backoff_ms to be set")
		return
	}

	initialBackoff := initialBackoffArg.GetIntValue()
	if initialBackoff != GRPC_INITIAL_BACKOFF_MS {
		t.Errorf("Expected initial backoff to be %d ms, got %d ms", GRPC_INITIAL_BACKOFF_MS, initialBackoff)
	}

	if initialBackoff != maxBackoff {
		t.Errorf("Expected initial and max backoff to be equal: initial=%d, max=%d",
			initialBackoff, maxBackoff)
	}

	t.Logf("Server Exception Scenario:")
	t.Logf("1. Connection succeeds")
	t.Logf("2. Server throws exception -> connection reset")
	t.Logf("3. Next reconnection attempt after %d ms (%v)",
		GRPC_INITIAL_BACKOFF_MS, time.Duration(GRPC_INITIAL_BACKOFF_MS)*time.Millisecond)
	t.Logf("4. Fixed backoff interval (no exponential growth) - all retries use %d ms",
		GRPC_MAX_BACKOFF_MS)
}

func TestGrpcChannelArgsConstants(t *testing.T) {
	setup()

	expectedValues := map[string]int64{
		"GRPC_MAX_PINGS_WITHOUT_DATA": 0,
		"GRPC_KEEPALIVE_TIME_MS":      10000,
		"GRPC_KEEPALIVE_TIMEOUT_MS":   20000,
		"GRPC_INITIAL_BACKOFF_MS":     10000, // 10 seconds initial backoff
	}

	actualValues := map[string]int64{
		"GRPC_MAX_PINGS_WITHOUT_DATA": GRPC_MAX_PINGS_WITHOUT_DATA,
		"GRPC_KEEPALIVE_TIME_MS":      GRPC_KEEPALIVE_TIME_MS,
		"GRPC_KEEPALIVE_TIMEOUT_MS":   GRPC_KEEPALIVE_TIMEOUT_MS,
		"GRPC_INITIAL_BACKOFF_MS":     GRPC_INITIAL_BACKOFF_MS,
	}

	for name, expected := range expectedValues {
		actual := actualValues[name]
		if actual != expected {
			t.Errorf("Expected %s to be %d, got %d", name, expected, actual)
		}
	}

	if GRPC_INITIAL_BACKOFF_MS != 10000 {
		t.Errorf("Expected GRPC_INITIAL_BACKOFF_MS to be 10000ms (10 seconds), got %d", GRPC_INITIAL_BACKOFF_MS)
	}
}
