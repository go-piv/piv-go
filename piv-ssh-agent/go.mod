module github.com/ericchiang/piv-go/piv-ssh-agent

// This modules exists so the top level package doesn't have to import
// everything that the agent depends on.

go 1.13

require (
	github.com/ericchiang/piv-go v0.0.0
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d
)

replace github.com/ericchiang/piv-go => ../
