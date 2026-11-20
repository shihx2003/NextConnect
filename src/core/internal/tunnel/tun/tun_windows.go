//go:build windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wintunRingCapacity = 0x400000 // 4 MiB ring buffer
	errorNoMoreItems   = windows.Errno(259)
	errorHandleEOF     = windows.Errno(38)
	createNoWindow     = 0x08000000
)

// QueryCapabilities 检测 Windows 宿主机是否存在 wintun.dll 以及当前进程是否拥有管理员权限。
func QueryCapabilities() Capabilities {
	wintunPath := findWintunDLL()
	return Capabilities{
		Platform:        runtime.GOOS,
		WintunAvailable: wintunPath != "",
		Elevated:        isProcessElevated(),
		AdapterName:     DefaultAdapterName,
		WintunPath:      wintunPath,
	}
}

// StartPlatformBridge 创建 Wintun 虚拟网卡、配置校园网静态分流路由并启动数据转发；Close() 时自动回收全部路由。
func StartPlatformBridge(
	ctx context.Context,
	cfg Config,
	bridge PacketBridge,
	onLog func(level, component, msg string),
) (*Manager, error) {
	wintunPath := findWintunDLL()
	if wintunPath == "" {
		return nil, ErrWintunNotFound
	}
	if !isProcessElevated() {
		return nil, ErrAdminRequired
	}
	if !cfg.VirtualIP.IsValid() || !cfg.VirtualIP.Is4() {
		return nil, fmt.Errorf("invalid tunnel virtual ip for wintun: %v", cfg.VirtualIP)
	}

	adapterName := strings.TrimSpace(cfg.AdapterName)
	if adapterName == "" {
		adapterName = DefaultAdapterName
	}
	prefixLen := cfg.PrefixLen
	if prefixLen <= 0 || prefixLen > 32 {
		prefixLen = 32
	}
	mtu := cfg.MTU
	if mtu < 576 {
		mtu = DefaultTunMTU
	}

	dev, err := openWintunDevice(wintunPath, adapterName, DefaultTunnelType)
	if err != nil {
		return nil, err
	}

	if err := dev.configureNetwork(cfg, prefixLen, mtu, onLog); err != nil {
		_ = dev.Close()
		return nil, err
	}

	mgr, err := StartBridgeWithDevice(ctx, dev, bridge, onLog)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return mgr, nil
}

type wintunAPI struct {
	dll                  *windows.LazyDLL
	createAdapter        *windows.LazyProc
	closeAdapter         *windows.LazyProc
	getAdapterLUID       *windows.LazyProc
	startSession         *windows.LazyProc
	endSession           *windows.LazyProc
	getReadWaitEvent     *windows.LazyProc
	receivePacket        *windows.LazyProc
	releaseReceivePacket *windows.LazyProc
	allocateSendPacket   *windows.LazyProc
	sendPacket           *windows.LazyProc
}

func loadWintunAPI(dllPath string) (*wintunAPI, error) {
	dll := windows.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("load %s failed: %w", dllPath, err)
	}
	return &wintunAPI{
		dll:                  dll,
		createAdapter:        dll.NewProc("WintunCreateAdapter"),
		closeAdapter:         dll.NewProc("WintunCloseAdapter"),
		getAdapterLUID:       dll.NewProc("WintunGetAdapterLUID"),
		startSession:         dll.NewProc("WintunStartSession"),
		endSession:           dll.NewProc("WintunEndSession"),
		getReadWaitEvent:     dll.NewProc("WintunGetReadWaitEvent"),
		receivePacket:        dll.NewProc("WintunReceivePacket"),
		releaseReceivePacket: dll.NewProc("WintunReleaseReceivePacket"),
		allocateSendPacket:   dll.NewProc("WintunAllocateSendPacket"),
		sendPacket:           dll.NewProc("WintunSendPacket"),
	}, nil
}

type wintunDevice struct {
	api         *wintunAPI
	name        string
	adapter     uintptr
	session     uintptr
	readEvent   windows.Handle
	luid        uint64
	addedRoutes []string
	bypassCmds  [][]string

	closeOnce sync.Once
	closed    chan struct{}
}

func openWintunDevice(dllPath string, name string, tunnelType string) (*wintunDevice, error) {
	api, err := loadWintunAPI(dllPath)
	if err != nil {
		return nil, err
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	typePtr, err := windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return nil, err
	}

	adapter, _, callErr := api.createAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(typePtr)),
		0,
	)
	if adapter == 0 {
		return nil, fmt.Errorf("WintunCreateAdapter failed: %w", callErr)
	}

	session, _, sessErr := api.startSession.Call(adapter, uintptr(wintunRingCapacity))
	if session == 0 {
		_, _, _ = api.closeAdapter.Call(adapter)
		return nil, fmt.Errorf("WintunStartSession failed: %w", sessErr)
	}

	readEventRaw, _, _ := api.getReadWaitEvent.Call(session)
	var luid uint64
	_, _, _ = api.getAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&luid)))

	return &wintunDevice{
		api:       api,
		name:      name,
		adapter:   adapter,
		session:   session,
		readEvent: windows.Handle(readEventRaw),
		luid:      luid,
		closed:    make(chan struct{}),
	}, nil
}

func (d *wintunDevice) Name() string {
	return d.name
}

func (d *wintunDevice) LUID() uint64 {
	return d.luid
}

func (d *wintunDevice) ReadPacket(buf []byte) (int, error) {
	for {
		select {
		case <-d.closed:
			return 0, errors.New("wintun adapter closed")
		default:
		}

		var pktSize uint32
		ptr, _, err := d.api.receivePacket.Call(
			d.session,
			uintptr(unsafe.Pointer(&pktSize)),
		)
		if ptr == 0 {
			if err == errorNoMoreItems {
				_, _ = windows.WaitForSingleObject(d.readEvent, 250)
				continue
			}
			if err == errorHandleEOF {
				return 0, errors.New("wintun session ended")
			}
			return 0, fmt.Errorf("WintunReceivePacket failed: %w", err)
		}

		n := int(pktSize)
		if n > len(buf) {
			n = len(buf)
		}
		copy(buf[:n], cMemSlice(ptr, n))
		_, _, _ = d.api.releaseReceivePacket.Call(d.session, ptr)
		return n, nil
	}
}

func (d *wintunDevice) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	select {
	case <-d.closed:
		return errors.New("wintun adapter closed")
	default:
	}

	ptr, _, err := d.api.allocateSendPacket.Call(d.session, uintptr(len(pkt)))
	if ptr == 0 {
		return fmt.Errorf("WintunAllocateSendPacket(%d) failed: %w", len(pkt), err)
	}
	dst := cMemSlice(ptr, len(pkt))
	copy(dst, pkt)
	_, _, _ = d.api.sendPacket.Call(d.session, ptr)
	return nil
}

func cMemSlice(addr uintptr, length int) []byte {
	// Wintun 环形缓冲区地址由非托管 DLL 分配，通过指针地址重解释构造视图并通过 go vet 检查。
	rawPtr := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return unsafe.Slice((*byte)(rawPtr), length)
}

func (d *wintunDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)

		// 先按逆序清理写入系统的路由，确保退出后零路由残留。
		for i := len(d.addedRoutes) - 1; i >= 0; i-- {
			_ = runHiddenNetCmd("netsh", "interface", "ipv4", "delete", "route",
				d.addedRoutes[i], fmt.Sprintf("interface=%s", d.name), "store=active")
		}
		for i := len(d.bypassCmds) - 1; i >= 0; i-- {
			_ = runHiddenNetCmd("route", d.bypassCmds[i]...)
		}

		if d.session != 0 {
			_, _, _ = d.api.endSession.Call(d.session)
			d.session = 0
		}
		if d.adapter != 0 {
			_, _, _ = d.api.closeAdapter.Call(d.adapter)
			d.adapter = 0
		}
	})
	return nil
}

func (d *wintunDevice) configureNetwork(
	cfg Config,
	prefixLen int,
	mtu int,
	onLog func(level, component, msg string),
) error {
	mask := prefixBitsToMask(prefixLen)
	if err := runHiddenNetCmd("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", d.name), "source=static",
		fmt.Sprintf("address=%s", cfg.VirtualIP.String()),
		fmt.Sprintf("mask=%s", mask),
		"store=active"); err != nil {
		return fmt.Errorf("assign wintun ipv4 failed: %w", err)
	}

	_ = runHiddenNetCmd("netsh", "interface", "ipv4", "set", "subinterface",
		d.name, fmt.Sprintf("mtu=%d", mtu), "store=active")

	if gwIP, ifIdx, err := discoverDefaultIPv4Gateway(); err == nil && gwIP != "" {
		for _, ip := range cfg.BypassIPs {
			if !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			args := []string{"add", ip.String(), "mask", "255.255.255.255", gwIP, "metric", "5", "if", ifIdx}
			if rErr := runHiddenNetCmd("route", args...); rErr == nil {
				d.bypassCmds = append(d.bypassCmds, []string{"delete", ip.String(), "mask", "255.255.255.255", gwIP})
			}
		}
	}

	routes := FilterCampusRoutes(cfg.Routes)
	for _, prefix := range routes {
		cidr := prefix.String()
		if err := runHiddenNetCmd("netsh", "interface", "ipv4", "add", "route",
			fmt.Sprintf("prefix=%s", cidr),
			fmt.Sprintf("interface=%s", d.name),
			"metric=10",
			"store=active"); err == nil {
			d.addedRoutes = append(d.addedRoutes, cidr)
		}
	}

	if onLog != nil {
		onLog("info", "tun", fmt.Sprintf("Wintun adapter %q configured (vip=%s/%d, campusRoutes=%d)",
			d.name, cfg.VirtualIP, prefixLen, len(d.addedRoutes)))
	}
	return nil
}

func prefixBitsToMask(bits int) string {
	if bits <= 0 {
		return "0.0.0.0"
	}
	if bits >= 32 {
		return "255.255.255.255"
	}
	var mask uint32 = 0xffffffff << uint(32-bits)
	return fmt.Sprintf("%d.%d.%d.%d", (mask>>24)&0xff, (mask>>16)&0xff, (mask>>8)&0xff, mask&0xff)
}

func findWintunDLL() string {
	candidates := make([]string, 0, 5)
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, "wintun.dll"),
			filepath.Join(exeDir, "resources", "core", "wintun.dll"),
		)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "wintun.dll"),
			filepath.Join(cwd, "dist", "wintun.dll"),
		)
	}
	if sysDir, err := windows.GetSystemDirectory(); err == nil {
		candidates = append(candidates, filepath.Join(sysDir, "wintun.dll"))
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func isProcessElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer func() { _ = token.Close() }()
	return token.IsElevated()
}

func runHiddenNetCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func discoverDefaultIPv4Gateway() (string, string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 1; if ($r) { Write-Output ($r.NextHop + ' ' + $r.InterfaceIndex) }")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return "", "", errors.New("no default ipv4 gateway found")
	}
	return fields[0], fields[1], nil
}
