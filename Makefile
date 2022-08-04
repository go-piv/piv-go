.PHONY: test
test: lint
	go test -v ./...

.PHONY: lint
lint:
	staticcheck ./...

.PHONY: build
build: lint
	go build ./...
