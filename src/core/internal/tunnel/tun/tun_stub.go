//go:build !windows

package tun

import (
	"context"
	"runtime"
)

// QueryCapabilities 返回当前非 Windows 平台的虚拟网卡能力检测结果。
func QueryCapabilities() Capabilities {
	return Capabilities{
		Platform:        runtime.GOOS,
		WintunAvailable: false,
		Elevated:        false,
		AdapterName:     DefaultAdapterName,
	}
}

// StartPlatformBridge 在非 Windows 平台返回平台不支持错误。
func StartPlatformBridge(
	_ context.Context,
	_ Config,
	_ PacketBridge,
	_ func(level, component, msg string),
) (*Manager, error) {
	return nil, ErrTunUnsupportedPlatform
}
