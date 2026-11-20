//go:build windows

package protocol

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func bindDialerToInterface(dialer *net.Dialer, iface net.Interface) error {
	dialer.ControlContext = func(_ context.Context, network, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			handle := syscall.Handle(fd)
			if strings.HasSuffix(network, "6") {
				bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, ipv6UnicastIf, iface.Index)
				return
			}
			var raw [4]byte
			binary.BigEndian.PutUint32(raw[:], uint32(iface.Index))
			idx := *(*uint32)(unsafe.Pointer(&raw[0]))
			bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, ipUnicastIf, int(idx))
		})
		if err != nil {
			return err
		}
		return bindErr
	}
	return nil
}
