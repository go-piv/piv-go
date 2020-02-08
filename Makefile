.PHONY: build
build:
	cd piv-ssh-agent && go build -o ../bin/piv-ssh-agent *.go

.PHONY: test
test:
	go test -v ./...
	golint -set_exit_status ./...
	cd piv-ssh-agent && go test -v
	cd piv-ssh-agent && golint -set_exit_status .

.PHONY: deb
deb: build
	go build -o ./bin/pkg-deb ./internal/pkg-deb/*.go
	chmod 0755 ./bin/piv-ssh-agent
	./bin/pkg-deb \
			--control=release/deb/control \
			--file=./bin/piv-ssh-agent=/usr/bin/piv-ssh-agent \
			--out=./bin/piv-ssh-agent_0.1.0_amd64.deb
