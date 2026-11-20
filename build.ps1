param(
    [switch]$SkipUi
)

$ErrorActionPreference = 'Stop'
$rootDir = $PSScriptRoot
$coreDir = Join-Path $rootDir 'src\core'
$uiDir = Join-Path $rootDir 'src\ui'
$distDir = Join-Path $rootDir 'dist'

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

Write-Host '[1/2] Building Go core (nextconnect-core)...' -ForegroundColor Cyan
Push-Location $coreDir
try {
    go test ./...
    $coreExe = Join-Path $distDir 'nextconnect-core.exe'
    go build -trimpath -ldflags '-s -w' -o $coreExe ./cmd/nextconnect-core
    Write-Host "Core built successfully: $coreExe" -ForegroundColor Green
}
finally {
    Pop-Location
}

if (-not $SkipUi) {
    Write-Host '[2/2] Type-checking UI (Electron + React + TS)...' -ForegroundColor Cyan
    Push-Location $uiDir
    try {
        if (-not (Test-Path 'node_modules')) {
            Write-Host 'node_modules not found. Run "npm install" inside src/ui first.' -ForegroundColor Yellow
        }
        else {
            npm run typecheck
            npm run build
        }
    }
    finally {
        Pop-Location
    }
}
