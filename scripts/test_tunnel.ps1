param(
    [string]$Gateway = '',
    [string]$Username = '',
    [string]$Mode = 'rule',
    [string]$SocksAddr = '127.0.0.1:10808',
    [string]$HttpAddr = '127.0.0.1:10809',
    [string]$ControllerAddr = '127.0.0.1:9090',
    [switch]$TunnelProbe
)

$ErrorActionPreference = 'Stop'
$rootDir = Split-Path -Parent $PSScriptRoot
$coreExe = Join-Path $rootDir 'dist\nextconnect-core.exe'

if ([string]::IsNullOrWhiteSpace($Gateway)) {
    $Gateway = $env:NEXTCONNECT_GATEWAY
}
if ([string]::IsNullOrWhiteSpace($Gateway)) {
    $Gateway = Read-Host '请输入目标 SSL VPN 网关地址（例如 https://vpn.example.edu）'
}

if (-not (Test-Path $coreExe)) {
    throw "未找到 $coreExe，请先运行 NextConnect\build.ps1 -SkipUi 编译或编译 src/core。"
}

if ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host '请输入 VPN 账号'
}

$securePwd = Read-Host '请输入 VPN 密码（输入时不显示明文）' -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd)
try {
    $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $env:NEXTCONNECT_TEST_PASS = $plainPwd

    if ($TunnelProbe) {
        Write-Host "[1/1] 正在测试 Port 443 L3IP 握手与虚拟 IP 分配 ($Gateway) ..." -ForegroundColor Cyan
        & $coreExe -tunnel-probe -gateway $Gateway -user $Username
        exit $LASTEXITCODE
    }

    Write-Host "正在启动 NextConnect 无头隧道内核 ($Gateway, mode=$Mode)..." -ForegroundColor Cyan
    Write-Host "  SOCKS5 代理 : $SocksAddr" -ForegroundColor Gray
    Write-Host "  HTTP/PAC    : http://$HttpAddr/proxy.pac" -ForegroundColor Gray
    Write-Host "  控制 API    : http://$ControllerAddr/api/v1/status" -ForegroundColor Gray
    Write-Host "  提示: 按 Ctrl+C 可停止内核并自动注销会话。" -ForegroundColor Yellow
    & $coreExe -connect -gateway $Gateway -user $Username -mode $Mode -socks $SocksAddr -http $HttpAddr -controller $ControllerAddr
    exit $LASTEXITCODE
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Item Env:NEXTCONNECT_TEST_PASS -ErrorAction SilentlyContinue
}
