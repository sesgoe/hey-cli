//go:build unix

// hey-gordy is the restricted HEY CLI an agent reaches over SSH: it reads and
// organizes mail and writes drafts, and cannot send. See internal/cmd/restricted.go.
package main

import "github.com/basecamp/hey-cli/internal/cmd"

func main() {
	cmd.ExecuteRestricted()
}
