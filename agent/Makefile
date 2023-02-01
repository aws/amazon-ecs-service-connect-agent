# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#	http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

.PHONY: build format test go-build clean run vendor

OSARCH = $(shell arch)
ifeq ($(OSARCH), x86_64)
ARCH=amd64
else ifeq ($(OSARCH), aarch64)
ARCH=arm64
endif

SRCS := $(wildcard *.go) \
	$(wildcard config/*.go) \
	$(wildcard envoy_bootstrap/*.go) \
	$(wildcard envoy_bootstrap/env/*.go) \
	$(wildcard envoy_bootstrap/mesh_resource/*.go) \
	$(wildcard envoy_bootstrap/metric_filter/*.go) \
	$(wildcard envoy_bootstrap/netinfo/*.go) \
	$(wildcard envoy_bootstrap/applicationinfo/*.go) \
	$(wildcard envoy_bootstrap/listenerinfo/*.go) \
	$(wildcard envoy_bootstrap/platforminfo/*.go) \
	$(wildcard healthcheck/*.go) \
	$(wildcard listenerdraining/*.go) \
	$(wildcard logging/*.go) \
	$(wildcard messagesources/*.go) \
	$(wildcard server/*.go) \
	$(wildcard client/*.go) \
	$(wildcard stats/*.go) \

build: test go-build

vendor:
	go mod vendor

format: $(SRCS)
	go fmt ./...

test: $(SRCS) format
	go test -mod=vendor -count=1 -v ./...

go-build: $(SRCS) format
	GOPATH=$(shell pwd)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -mod=vendor -ldflags "-w -s"

clean:
	go clean
