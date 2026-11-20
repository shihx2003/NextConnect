//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func isStdinTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

func readPasswordWithNoEcho(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return readPlainLine(prompt)
	}

	newState := *oldState
	newState.Lflag &^= unix.ECHO
	newState.Lflag |= unix.ICANON | unix.ISIG
	newState.Iflag |= unix.ICRNL

	fmt.Fprint(os.Stderr, prompt)
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &newState); err != nil {
		return "", fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, oldState)
		fmt.Fprintln(os.Stderr)
	}()

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	trimmed := strings.TrimRight(line, "\r\n")
	if err != nil && trimmed == "" {
		return "", err
	}
	return trimmed, nil
}
