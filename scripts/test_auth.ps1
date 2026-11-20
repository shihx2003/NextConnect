param(
    [string]$Gateway = '',
    [string]$Username = '',
    [switch]$ProbeOnly
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
    Write-Host "未找到 $coreExe，正在尝试自动编译 Go 内核..." -ForegroundColor Yellow
    $coreSrc = Join-Path $rootDir 'src\core'
    Push-Location $coreSrc
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path $coreExe) | Out-Null
        go build -trimpath -ldflags '-s -w' -o $coreExe ./cmd/nextconnect-core
    }
    finally {
        Pop-Location
    }
}

if ($ProbeOnly) {
    Write-Host "[1/1] 正在探测网关 $Gateway 认证能力（无需账号密码）..." -ForegroundColor Cyan
    & $coreExe -probe -gateway $Gateway
    exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host '请输入 VPN 账号'
}

$securePwd = Read-Host '请输入 VPN 密码（输入时不显示明文）' -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd)
try {
    $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $env:NEXTCONNECT_TEST_PASS = $plainPwd
    Write-Host "正在测试认证网关 $Gateway ..." -ForegroundColor Cyan
    & $coreExe -auth-test -gateway $Gateway -user $Username
    exit $LASTEXITCODE
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Item Env:NEXTCONNECT_TEST_PASS -ErrorAction SilentlyContinue
}
