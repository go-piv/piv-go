.PHONY: build
build:
	cd piv-ssh-agent && go build -o ../bin/piv-ssh-agent *.go

.PHONY: test
test:
	go test -v ./piv
	golint -set_exit_status ./piv
	cd piv-ssh-agent && go test -v
	cd piv-ssh-agent && golint -set_exit_status .
