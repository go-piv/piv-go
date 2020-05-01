.PHONY: test
test: lint
	go test -v ./...

.PHONY: lint
lint:
	golint -set_exit_status ./...

.PHONY: build
build: lint
	go build ./...
