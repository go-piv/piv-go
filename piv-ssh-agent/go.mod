module github.com/ericchiang/piv-go/piv-ssh-agent

// This modules exists so the top level package doesn't have to import
// everything that the agent depends on.

go 1.13

require github.com/ericchiang/piv-go v0.0.0

replace github.com/ericchiang/piv-go => ../
