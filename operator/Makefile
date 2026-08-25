IMAGE ?= ghcr.io/shkevin/vat/operator:latest

.PHONY: test
test:
	go test ./...

.PHONY: build
build:
	CGO_ENABLED=0 go build -o bin/vat-operator ./cmd/vat-operator

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE) .
