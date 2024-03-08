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
