.PHONY: test
test:
	go test -v ./...

.PHONY: build
build:
	go build ./...

.PHONY: clean
clean:
	go clean ./...
