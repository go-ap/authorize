SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

PROJECT_NAME := auth
ENV ?= dev
STORAGE ?=

LDFLAGS ?= -X main.version=$(VERSION)
BUILDFLAGS ?= -a -ldflags '$(LDFLAGS)'
TEST_FLAGS ?= -count=1

GO ?= go
APPSOURCES := $(wildcard ./*.go cmd/auth/*.go)

TAGS := $(ENV)
ifneq ($(STORAGE), )
	TAGS +=  storage_$(STORAGE)
endif

export CGO_ENABLED=0

ifneq ($(ENV), dev)
	LDFLAGS += -s -w -extldflags "-static"
	BUILDFLAGS += -trimpath
endif

ifeq ($(shell git describe --always > /dev/null 2>&1 ; echo $$?), 0)
	BRANCH=$(shell git rev-parse --abbrev-ref HEAD | tr '/' '-')
	HASH=$(shell git rev-parse --short HEAD)
	VERSION ?= $(shell printf "%s-%s" "$(BRANCH)" "$(HASH)")
endif
ifeq ($(shell git describe --tags > /dev/null 2>&1 ; echo $$?), 0)
	VERSION ?= $(shell git describe --tags | tr '/' '-')
endif

BUILD := $(GO) build $(BUILDFLAGS)
TEST := $(GO) test $(BUILDFLAGS)

.PHONY: all auth download run clean images test coverage

all: auth

download: go.sum

go.sum: go.mod
	$(GO) mod download all
	$(GO) mod tidy

auth: bin/auth
bin/auth: go.mod go.sum $(APPSOURCES)
	$(BUILD) -tags "$(TAGS)" -o $@ ./cmd/auth

run: ./bin/auth
	@./bin/auth

clean:
	-$(RM) bin/*
	$(MAKE) -C images $@

images:
	$(MAKE) -C images $@

test: TEST_TARGET := .
test: go.sum
	$(TEST) $(TEST_FLAGS) -tags "$(TAGS)" $(TEST_TARGET)

coverage: TEST_TARGET := .
coverage: TEST_FLAGS += -covermode=count -coverprofile $(PROJECT_NAME).coverprofile
coverage: test
