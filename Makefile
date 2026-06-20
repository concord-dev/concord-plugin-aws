BIN := bin/concord-plugin-aws
VERSION ?= v0.1.0
INSTALL_DIR := $(HOME)/.concord/plugins/aws/$(VERSION)

.PHONY: build install clean

build:
	go build -o $(BIN) ./cmd/concord-plugin-aws

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BIN) $(INSTALL_DIR)/concord-plugin-aws

clean:
	rm -rf bin
