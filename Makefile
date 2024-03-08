GOBIN                   ?=$(shell go env GOPATH)/bin
GOVERSION               ?=$(shell grep '^go' go.mod | awk '{print $$2}' | head -1)

.PHONY: test
test:
	go test -v ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: build
build: lint  test
	go build ./...

.PHONY: clean
clean:
	go clean ./...

mod-update:
	go get  -u ./...
	$(MAKE) mod

mod:
	go mod tidy -compat=$(GOVERSION)
	go mod vendor

