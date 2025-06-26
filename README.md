# Threat Event: Payload Delivery and Persistence via PowerShell
Simulated Malware Delivery Using PowerShell and Scheduled Task Creation for Persistence
- [Scenario Creation](hhttps://github.com/aduragbemioo/Threat-Event-Suspicious-Use-of-Certutil-for-Payload-Download/blob/main/scenario.md)


🛠️ Platforms and Tools Used
Windows 10 Virtual Machine (Microsoft Azure)
EDR Platform: Microsoft Defender for Endpoint
PowerShell
Kusto Query Language (KQL)
Simulated Payload (payload.exe)


📘 Scenario
🚨 Organizational Monitoring Directive
Due to increased phishing and malware delivery attempts using LOLBins like certutil.exe, the organization initiated a proactive hunt for suspicious payload delivery and persistence mechanisms. 

🔍 Investigation Steps
🔹 1. Detection of PowerShell-Based Payload Delivery
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("Invoke-WebRequest", "-OutFile", "EncodedCommand")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

- Multiple suspicious PowerShell commands using Invoke-WebRequest and -OutFile were detected.
- This indicates likely attempts to download and write payloads using allowed LOLBins.

🔹 2. Detection of Payload Dropped in Public Folder
```kusto
DeviceFileEvents
| where DeviceName == "ad-stig-impleme"
| where FolderPath contains "C:\\Users\\Public"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessCommandLine
```
- Simulated payload, payload.exe, was discovered in C:\Users\Public.
- This directory is commonly abused for shared access or loose permission settings.

🔹 3. Check for Payload Execution
```kusto
DeviceProcessEvents
| where DeviceName == "ad-stig-impleme"
| where FolderPath contains "C:\\Users\\Public"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

```
- No record of execution found, this is expected since the payload was non-functional (fake).
- In a real-world attack, execution would trigger Defender and generate logs.


🔹 4. Check for Scheduled Task Creation for Persistence

```kusto
DeviceProcessEvents
| where DeviceName == "ad-stig-impleme"
| where ProcessCommandLine has_all("schtasks", "/create")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

```
- Detected creation of a scheduled task using schtasks /create
- Scheduled tasks are a common persistence technique and are often abused in malware deployment
  
### Chronological Event Timeline
### 1. Suspicious File Drop
- **Timestamp:** See DeviceFileEvents log from PowerShell download
- **Event:** Dropped payload.exe into the C:\Users\Public directory using Invoke-WebRequest.
- **Path:** C:\Users\Public\fakepayload.exe

### 2. Scheduled Task Persistence Established
- **Timestamp:** Timestamp from scheduled task creation event
- **Event:** Scheduled task created via PowerShell using schtasks /create.
- **Command Line:** schtasks /create /tn "Updater" /tr "C:\Users\Public\fakepayload.exe" /sc onlogon

### 3. Attempted Execution of Payload
- **Timestamp:** Not recorded (fake executable not run)
- **Event:** No execution of fakepayload.exe was observed. Expected in a real attack to trigger via task or direct run.

### 4. LOLBin Abuse Using PowerShell
- **Timestamp:** During initial payload delivery
- **Event:** PowerShell used Invoke-WebRequest as an alternative to blocked certutil.exe.


### 5. No Network Exfiltration or Lateral Movement Detected
- **Event:** No connections to external IPs or domains were initiated by the payload.
Note: Suggests the payload was non-functional or environment blocked outbound behavior.

🧾 Summary of Hunt Findings
A simulated malware delivery operation was conducted using PowerShell. The payload was delivered via Invoke-WebRequest and saved to a commonly abused directory (C:\Users\Public). Persistence was attempted using a scheduled task.

- Affected Device: ad-stig-impleme

- Techniques Simulated:

-- Living-off-the-land payload delivery

-- Scheduled task creation for persistence

- Defender logs confirmed:

-- PowerShell download attempt

-- Payload write activity

-- Task scheduler usage

✅ Response Taken
The device ad-stig-impleme was marked for observation.

Events were logged and stored for future SOC tuning and detection rule validation.

Blocklist policies were reviewed to ensure LOLBin coverage beyond certutil.exe.
