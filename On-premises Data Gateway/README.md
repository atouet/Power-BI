c# Windows Troubleshooting Data Collector `v0.7`
Interactive PowerShell script that gathers the most common diagnostics needed by support engineers—without hunting through MMC snap-ins or registry hives yourself.

---

## ✨ Key Features
| Scenario | Collects | Typical Use-case |
|----------|----------|------------------|
| **1 – Logs only** | `SystemInfo.txt` &nbsp;+ Windows **Application / System / Security** event logs (past 7 days) | General health check; offline log review |
| **2 – Live traces** | High-level **network ETL** (`.etl`) &nbsp;+ lightweight **PerfMon** (`.blg`) while you reproduce an issue | Connectivity issues, performance issues |
| **3 – Full capture** | Everything from Scenario&nbsp;2 **plus** CAPI2/Operational log and all files from Scenario&nbsp;1 | complex scenarios, connectivity issues including SSL/TLS failures, performance issues, general server information) |

All output is stored in a time-stamped directory:

    <base-path>\MSTraces_YYYYMMDD-HHMMSS\

---

## 🔧 Prerequisites
* Windows Server 2016 and above
* **Administrator** rights (script checks and exits if not elevated)  
* PowerShell 5.x or newer (comes with Windows)  

---

## 🚀 Quick Start

    # 1. Clone the repo
    git clone https://github.com/<org>/<repo>.git
    cd <repo>

    # 2. Start an elevated PowerShell console
    # 3. Run the script
    .\Collect-WinDiagnostics.ps1

You will see a banner similar to:

    Windows Troubleshooting Data Collector  v0.7
    ─────────────────────────────────────────────────────────
    ▪ Scenario 1 – System info + core event logs
    ▪ Scenario 2 – Live network ETL trace + PerfMon
    ▪ Scenario 3 – Full capture (trace + CAPI2 + logs)

Follow the prompts to choose a scenario and base folder.

---

## 📂 What Gets Collected?

### 1. `SystemInfo_<timestamp>.txt`
A single, human-readable snapshot with:

| Section | Details |
|---------|---------|
| **Network** | Primary IPv4 address (non-loopback), WinHTTP proxy, IE proxy settings |
| **CPU / Memory** | Physical cores, logical processors, total RAM (GB) |
| **OS Build** | Major.Minor.Build.Revision & friendly name (`Build 22631` etc.) |
| **.NET Runtime** | Highest installed desktop CLR 4.x version (registry Release → version) |
| **Firewall** | `netsh advfirewall show allprofiles` dump—profile states & rules summary |
| **Antivirus** | Display name(s) reported by `root/SecurityCenter2:AntivirusProduct` |
| **Installed Programs** | `DisplayName` + `DisplayVersion` from the traditional *Uninstall* registry key |

> **Tip:** Because it is plain text you can search for build numbers, proxy strings, AV vendors, etc.

---

### 2. Windows Event Logs (`.evtx`)
| Scenario | Channels Exported | Time Range |
|----------|------------------|------------|
| 1 | Application, System, Security | Last **7 days** |
| 3 | Same as Scenario 1 **plus** `Microsoft-Windows-CAPI2/Operational` | Last **7 days** |

Export is done via **`wevtutil epl`** with an XPath time filter, so original event IDs and metadata are preserved.

---

### 3. Network Trace (`Trace_<PC>_<timestamp>.etl`)
Circular **ETL** created with **`netsh trace start scenario=netconnection,internetclient`** and extra packet-level providers (NDIS, TCPIP, Winsock-AFD, Schannel, etc.).

* Max size 4 GB (overwrites when full).  
* Capture stops automatically when you type **`stop`**.

Open with **Wireshark** (`etl` import), **Microsoft Message Analyzer** (retired) or **NetMon**.

---

### 4. Performance Monitor (`Perfmon_<tim_
