# Author: Alexis Touet
# Version: v0.1
# Date: 2025-06-15
# Summary: This script collects network ETL trace, Windows event logs, performance monitor metrics, and other Windows Server information.

# Step 0: Check for Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

# Step 1: Create MSTraces_<timestamp> folder on a non-C drive if available
Write-Host "`n[Step 1] Creating MSTraces folder..."
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }
$logDrive = $drives | Where-Object { $_.Name -ne "C" } | Select-Object -First 1
if (-not $logDrive) {
    $logDrive = $drives | Where-Object { $_.Name -eq "C" } | Select-Object -First 1
}
$logPath = "$($logDrive.Name):\MSTraces_$timestamp"
New-Item -Path $logPath -ItemType Directory -Force | Out-Null

# Step 2: Collect System Information
Write-Host "`n[Step 2] Collecting system information..."
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
$cpuCores = (Get-WmiObject Win32_Processor).NumberOfCores
$vCores = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
$ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)

# Proxy settings
$webproxy = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
$proxyEnabled = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable
$winhttpProxy = netsh winhttp show proxy | Out-String

# Firewall and OS info
$firewall = netsh advfirewall show allprofiles | Out-String
$osVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName

# .NET version
$dotnet = $null
try {
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name InstallPath,Release -ErrorAction Stop
    $dotnet = switch -regex ($reg.Release) {
        "378389" { "4.5" }
        "378675|378758" { "4.5.1" }
        "379893" { "4.5.2" }
        "393295|393297" { "4.6" }
        "394254|394271" { "4.6.1" }
        "394802|394806" { "4.6.2" }
        "460798|460805" { "4.7" }
        "461308|461310" { "4.7.1" }
        "461808|461814" { "4.7.2" }
        "528040|528049" { "4.8" }
        "533320" { "4.8.1" }
        {$_ -gt 533320} { "Newer than 4.8.1+" }
    }
} catch {
    $dotnet = "Not found"
}

# Installed programs and antivirus
$programs = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName }
$antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName

# Save system info
$sysInfo = @"
IP Address: $ip
CPU Cores: $cpuCores
vCores: $vCores
RAM: $ram GB
IE Proxy Server: $webproxy
Proxy Enabled: $proxyEnabled
WinHTTP Proxy Settings:
$winhttpProxy
Firewall:
$firewall
Windows Version: $osVersion
.NET Version: $dotnet
Antivirus: $($antivirus.displayName)
Installed Programs:
$($programs | Format-Table | Out-String)
"@
$sysInfo | Out-File "$logPath\SystemInfo.txt"

# Step 3: Start Performance Monitor
Write-Host "`n[Step 3] Starting performance monitor..."
$perfmonName = "Perfmon_$timestamp"
$perfLog = "$logPath\$perfmonName.blg"
if (logman query $perfmonName -ets > $null 2>&1) {
    logman delete $perfmonName -ets
}
logman create counter $perfmonName `
  -counters "\Processor(_Total)\% Processor Time" `
            "\Memory\Available MBytes" `
            "\Memory\Committed Bytes" `
            "\PhysicalDisk(_Total)\% Idle Time" `
            "\PhysicalDisk(_Total)\Current Disk Queue Length" `
  -f bin -o "$perfLog" -si 00:00:05
logman start $perfmonName

# Step 4: Start Network Trace
Write-Host "`n[Step 4] Starting network trace..."
$traceFile = "$logPath\Trace_$env:COMPUTERNAME_$timestamp.etl"
netsh trace start scenario=netconnection,internetclient capture=yes report=yes overwrite=yes maxsize=4096 tracefile="$traceFile" provider="Microsoft-Windows-NDIS" keywords=0xffffffffffffffff level=0xff provider="Microsoft-Windows-TCPIP" keywords=0x80007fff000000ff level=0x5 provider="{EB004A05-9B1A-11D4-9123-0050047759BC}" keywords=0x3ffff level=0x5 provider="Microsoft-Windows-Winsock-AFD" keywords=0x800000000000003f level=0x5 provider="{B40AEF77-892A-46F9-9109-438E399BB894}" keywords=0xffffffffffffffff level=0xff

# Step 5: Wait for 'stop' input
Write-Host "`n[Step 5] Monitoring in progress. Type 'stop' to end monitoring..."
do {
    $input = Read-Host "Type 'stop' to end monitoring"
} while ($input -ne "stop")

Write-Host "Stopping monitoring... Please wait while logs are being collected."

# Step 6: Stop Performance Monitor and Network Trace
Write-Host "`n[Step 6] Stopping traces..."
logman stop $perfmonName
netsh trace stop

# Step 7: Export Windows Event Logs
Write-Host "`n[Step 7] Exporting Windows event logs..."
$logs = @("Application", "System", "Security")
foreach ($log in $logs) {
    $logFile = "$logPath\$log.evtx"
    wevtutil epl $log "$logFile" /q:"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
}

# Step 8: Final Check
Write-Host "`n[Step 8] Verifying saved logs..."
$expectedFiles = @(
    "$logPath\\SystemInfo.txt",
    (Get-ChildItem -Path $logPath -Filter "$perfmonName*.blg").FullName,
    "$traceFile",
    "$logPath\\Application.evtx",
    "$logPath\\System.evtx",
    "$logPath\\Security.evtx"
)

$missing = @()
foreach ($file in $expectedFiles) {
    if (-not (Test-Path $file)) {
        $missing += $file
    }
}

if ($missing.Count -eq 0) {
    Write-Output "`n✅ All logs and traces saved to $logPath"
} else {
    Write-Output "`n❌ Error: The following files were not saved successfully:"
    $missing | ForEach-Object { Write-Output "- $_" }
}
