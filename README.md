# My Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Tochiughasoro/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had string “tor” in it and discovered what looks like the user “greatness” downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop and the creation of a file called `tor-shoppoing-list.txt` on the desktop at `2026-05-17T02:44:51.6251131Z`. These events began at `2026-05-18T15:17:41.9052062Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "toks-threat-lab"
| where InitiatingProcessAccountName == "greatness"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-05-18T15:17:41.9052062Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1400" height="637" alt="Screenshot 2026-05-20 at 15 47 05" src="https://github.com/user-attachments/assets/d4464645-d9b1-40a6-ab73-d649910857ad" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.13.exe”. Based on the logs returned, `2026-05-18T16:20:45`, the user account “greatness” on the device “toks-threat-lab” launched the file `tor-browser-windows-x86_64-portable-15.0.13.exe` from the Downloads folder, was executed on the system using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "toks-threat-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.13.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1409" height="198" alt="Screenshot 2026-05-20 at 16 19 17" src="https://github.com/user-attachments/assets/1f60366e-3bbd-45ea-b1bd-b1520b8dbfab" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Search for any indication that user “greatness” actually opened the TOR browser. There was evidence that they did open it at `2026-05-18T15:24:10.4878653Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "toks-threat-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1290" height="647" alt="Screenshot 2026-05-20 at 17 08 07" src="https://github.com/user-attachments/assets/dbb75f17-c8a0-43b8-977d-03053b8345f6" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the tor browser was used to establish a connection using any of the known TOR ports. At `2026-05-18T16:24:40`, the user account “greatness” on the device “toks-threat-lab” successfully established a network connection using firefox.exe located in the Tor Browser directory `c:\Users\greatness\Desktop\Tor Browser\Browser\firefox.exe`. The browser connected to the local IP address `127.0.0.1` over port `9150`, a port commonly used by Tor Browser as a local SOCKS proxy, indicating that the browser was routing traffic through the Tor network over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "toks-threat-lab"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9030", "9040", "9050", "9051", "9053", "9061", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1357" height="206" alt="Screenshot 2026-05-20 at 17 25 20" src="https://github.com/user-attachments/assets/c637b706-3e7a-46dd-a9c5-55c5912ac702" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-18T16:17:41.6065231Z`
- **Event:** The user "greatness" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.13.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Greatness\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`
This event marks the first confirmed evidence of Tor Browser being introduced onto the endpoint.

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-18T16:20:45.4484567Z`
- **Event:** The user "greatness" executed the file `tor-browser-windows-x86_64-portable-15.0.13.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.13.exe /S`
- **File Path:** `C:\Users\greatness\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-05-18T16:24:01.6357935Z`
- **Event:** User "greatness" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\greatness\Desktop\Tor Browser\Browser\TorBrowser\Tor\firefox.exe

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-05-18T16:24:14.1246358Z`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` by user "greatness" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\greatness\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**`2026-05-18T16:24:Z` - A successful Tor-related network connection was observed.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "greatness" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-18T17:27:19.7259964Z`
- **Event:** The user "greatness" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The investigation confirmed that user "greatness" on the "toks-threat-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `toks-threat-lab` by the user `greatness`. The device was isolated, and the user's direct manager was notified.

---
