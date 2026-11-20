//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func isStdinTerminal() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}

func readPasswordWithNoEcho(prompt string) (string, error) {
	h := windows.Handle(os.Stdin.Fd())
	var oldMode uint32
	if err := windows.GetConsoleMode(h, &oldMode); err != nil {
		// 非原生 Windows 控制台（如管道或某些终端仿真器）时回退普通读取。
		return readPlainLine(prompt)
	}

	fmt.Fprint(os.Stderr, prompt)
	newMode := oldMode &^ windows.ENABLE_ECHO_INPUT
	if err := windows.SetConsoleMode(h, newMode); err != nil {
		return "", fmt.Errorf("disable console echo: %w", err)
	}
	defer func() {
		_ = windows.SetConsoleMode(h, oldMode)
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
