[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Serial,
    [string]$SdkRoot = "$env:LOCALAPPDATA/Android/Sdk",
    [string]$JdkRoot = $env:JAVA_HOME,
    [string]$BuildToolsVersion = '36.1.0',
    [switch]$SkipJni
)
$ErrorActionPreference = 'Stop'
$Project = Split-Path $PSScriptRoot -Parent
$Build = Join-Path $Project 'build_arm64'
$Adb = Join-Path $SdkRoot 'platform-tools/adb.exe'
$Log = Join-Path $Build "regression_$Serial.log"
$Remote = '/data/local/tmp/arm32bridge-regression'
Set-Content -LiteralPath $Log -Value "Android bridge regression: $Serial"
function Invoke-Adb {
    param([string[]]$NativeArgs)
    & $Adb -s $Serial @NativeArgs 2>&1 | Tee-Object -FilePath $Log -Append
    if ($LASTEXITCODE -ne 0) { throw "adb failed ($LASTEXITCODE): $NativeArgs" }
}
if (-not (Test-Path -LiteralPath "$Build/bridge_regression")) {
    throw 'Build tests first: ./build_arm64.ps1 -BuildTests'
}
Invoke-Adb @('push', "$Build/bridge_regression", $Remote)
# adb push can reset the execute bit even when replacing an existing binary.
Invoke-Adb @('shell', 'chmod', '755', $Remote)
Invoke-Adb @('shell', $Remote)
if (-not $SkipJni) {
    if (-not $JdkRoot) { throw 'Pass -JdkRoot or set JAVA_HOME to build the ART test.' }
    $JniOut = Join-Path $Build 'jni_test'
    New-Item -ItemType Directory -Force -Path $JniOut | Out-Null
    & "$JdkRoot/bin/javac.exe" --release 8 -Xlint:-options -d $JniOut "$PSScriptRoot/BridgeJniRegression.java"
    if ($LASTEXITCODE -ne 0) { throw 'javac failed' }
    $PreviousJava = $env:JAVA_HOME
    try {
        $env:JAVA_HOME = $JdkRoot
        & "$SdkRoot/build-tools/$BuildToolsVersion/d8.bat" --min-api 26 --output $JniOut "$JniOut/BridgeJniRegression.class"
        if ($LASTEXITCODE -ne 0) { throw 'd8 failed' }
    } finally { $env:JAVA_HOME = $PreviousJava }
    Invoke-Adb @('push', "$Build/libbridge_jni_regression.so", "$Remote-jni.so")
    Invoke-Adb @('push', "$JniOut/classes.dex", "$Remote.dex")
    Invoke-Adb @('shell', "CLASSPATH=$Remote.dex app_process /system/bin BridgeJniRegression $Remote-jni.so")
}
Write-Output "Test log: $Log"
