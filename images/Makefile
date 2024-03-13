SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

ENV ?= dev
APP_HOSTNAME ?= auth
PORT ?= 4001
STORAGE ?= all
TAG ?= $(ENV)
VERSION ?= HEAD

BUILD_CMD=buildah bud
RUN_CMD=podman run
TAG_CMD=podman tag
PUSH_CMD=podman push

ifneq ($(STORAGE),all)
	TAG=$(ENV)-$(STORAGE)
endif

.PHONY: clean images cert build builder push

$(APP_HOSTNAME).pem:
	./gen-certs.sh auth

cert: $(APP_HOSTNAME).pem

clean:
	@-$(RM) $(APP_HOSTNAME).{key,crt,pem}

builder:
	./build.sh .. auth/builder

build:
	ENV=$(ENV) VERSION=$(VERSION) STORAGE=$(STORAGE) PORT=$(PORT) APP_HOSTNAME=$(APP_HOSTNAME) ./image.sh $(APP_HOSTNAME)/app:$(TAG)

push: build
	$(TAG_CMD) $(APP_HOSTNAME)/app:$(TAG) quay.io/go-ap/auth:$(TAG)
	$(PUSH_CMD) quay.io/go-ap/auth:$(TAG)
ifeq ($(TAG),dev)
	$(TAG_CMD) $(APP_HOSTNAME)/app:$(TAG) quay.io/go-ap/auth:latest || true
	$(PUSH_CMD) quay.io/go-ap/auth:latest || true
endif
ifneq ($(VERSION),)
	$(TAG_CMD) $(APP_HOSTNAME)/app:$(ENV) quay.io/go-ap/auth:$(VERSION)-$(TAG) || true
	$(PUSH_CMD) quay.io/go-ap/auth:$(VERSION)-$(TAG) || true
endif
