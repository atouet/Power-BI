# OPDG - Environmental Troubleshooting Data Collector `v0.7`
Interactive PowerShell script that gathers the most common windows diagnostics needed by support engineers in an automated way. 

---

## ✨ Key Features
| Scenario | Collects | Typical Use-case |
|----------|----------|------------------|
| **1 – Logs only** | `SystemInfo.txt` &nbsp;+ Windows **Application / System / Security** event logs (past 7 days) | General health check; offline log review |
| **2 – Live traces** | High-level **network ETL** (`.etl`) &nbsp;+ lightweight **PerfMon** (`.blg`) while you reproduce an issue | Connectivity issues, performance issues |
| **3 – Full capture** | Everything from Scenario&nbsp;2 **plus** CAPI2/Operational log and all files from Scenario&nbsp;1 | Complex scenarios, connectivity issues including SSL/TLS failures, performance issues, general server information) |

All output is stored in a time-stamped directory:

    <base-path>\MSTraces_YYYYMMDD-HHMMSS\

---

## 🔧 Prerequisites
* Windows Server 2019 and above
* **Administrator** rights (script checks and exits if not elevated)  
* PowerShell 5.x or newer (comes with Windows)  

---

## 🚀 Quick Start


    # 1. Start an elevated PowerShell console
    # 2. Run the script
    .\Collect-WinDiagnostics.ps1

You will see a banner similar to:

    OPDG - Environmental Troubleshooting Data Collector v0.7
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

### 4. Performance Monitor (`Perfmon_<timestamp>.blg`)
Counter set sampled every **5 seconds**:

* `\Processor(_Total)\% Processor Time`  
* `\Memory\Available MBytes`  
* `\Memory\Committed Bytes`  
* `\PhysicalDisk(_Total)\% Idle Time`  
* `\PhysicalDisk(_Total)\Current Disk Queue Length`  

Great for correlating CPU/RAM/disk spikes with packets in the ETL trace.

---

## 📏 Expected Folder Layout & Sizes

```
MSTraces_20250618-093245\
├─ SystemInfo_20250618-093245.txt            ~  5–20 KB
├─ Application_20250618-093245.evtx          ~  1–50 MB
├─ System_20250618-093245.evtx               ~  1–50 MB
├─ Security_20250618-093245.evtx             ~  1–10 MB
├─ Microsoft-Windows-CAPI2_Operational_...   (scenario 3 only)
├─ Trace_HOST123_20250618-093245.etl         up to 4 GB (circular)
└─ Perfmon_20250618-093245.blg               ~  2–50 MB
```

*Logs compress well*—zip/7-zip before uploading to reduce footprint.

---

## 🐛 Troubleshooting & FAQ

<details>
<summary><strong>“Script says ‘Please run as Administrator’ even though I am admin.”</strong></summary>

Launch PowerShell with **Run as administrator** (title bar shows *Administrator:*).  
Having admin rights in AD does not automatically elevate your shell.
</details>

<details>
<summary><strong>How do I view `.evtx` files on another machine?</strong></summary>

Copy the file and open with **Event Viewer → Action → Open Saved Log…**.  
No need to rename or import.
</details>

<details>
<summary><strong>Can I increase the log retention beyond 7 days?</strong></summary>

Yes—search for the variable **`$logDays`** in the script and adjust it.
</details>

<details>
<summary><strong>Does the script collect any personal files?</strong></summary>

No. It only queries system metadata, registry keys, and Windows logging APIs.  
Nothing from user documents, browser history, etc. is touched.
</details>

---

## 📜 License
MIT – do whatever you want, **no warranty**.

---

> Maintained with ❤️ by **Alexis Touet**. 
