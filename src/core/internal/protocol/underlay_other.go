//go:build !windows

package protocol

import "net"

func bindDialerToInterface(_ *net.Dialer, _ net.Interface) error {
	return nil
}
