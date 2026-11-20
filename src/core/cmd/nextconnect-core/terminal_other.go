//go:build !windows && !linux

package main

func isStdinTerminal() bool {
	return false
}

func readPasswordWithNoEcho(prompt string) (string, error) {
	return readPlainLine(prompt)
}
