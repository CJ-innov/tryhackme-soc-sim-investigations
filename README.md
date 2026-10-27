
# TryHackMe SOC Simulator - Investigations

SOC Level 1 investigations using Splunk. Correlating alerts, building kill-chains, and closing incidents as TP/FP.

**Analyst:** joshuachia67 | **SIEM:** Splunk Enterprise | **Platform:** TryHackMe

## Performance
- True Positive Identification Rate: **100%**
- False Positive Identification Rate: **86%**
- Verdict: `Victory! Security breach prevented!`

---

### Scenario 1: Phishing Unfolding / Introduction to Phishing
**Difficulty:** Easy | **Length:** 40 mins

**Summary:** Triage inbound email alerts to distinguish real phishing payloads from spam.

**Key Artifact:**
> Sender: `eileen@trendymillineryco.me`
> Recipient: `support@t8ythatme.com`
> Subject: `Inheritance Alert: Unknown Billionaire Relative Left You Their Hat Fortunes`
> Content: `A long lost billionaire relative has left you their secret hat empire To claim your inheritance send us your banking details immediately`

**Analysis:** Classic advance-fee / inheritance scam. Identified as phishing but not part of active compromise chain - correctly classified to improve FP rate.

**Skills:** Email analysis, Spam vs Phishing, Splunk `email` datasource

![Phishing Email](./screenshots/01-phishing-unfolding/email-phish.png)

### Scenario 2: Repossessed - Live Breach (Featured)
**Difficulty:** Medium | **Host:** win-3450 | **User:** SSF\michael.ascott

**This is a full kill-chain investigation.**

**Kill Chain Timeline (Oct 27 2026):**

| Time | Alert | Technique | Detail |
| --- | --- | --- | --- |
| 10:33 | 1005 | T1566.001 | Phishing - `ImportantInvoice-February.zip` executed |
| 10:55 | 1020 | T1588.002 | Tooling - `PowerView.ps1` created in Downloads (PID 9060) |
| 10:57 | 1022 | T1039 | Discovery - `powershell PID 3728 -> net.exe use Z: \\FILESRV-01\SSF-FinancialRecords` |
| 10:58 | 1023 | T1074.001 / T1005 | Collection - `Robocopy.exe /E C:\Users\...\exfiltration Z:\` |
| 10:58 | 1024 | T1070.004 | Anti-Forensics - `net.exe use Z: /delete` cleanup |
| 10:59 | C2 | T1572 | C2 - PowerCat reverse shell to `2.tcp.ngrok.io:19282` |
| 11:00 | 1030-1034 | T1048.003 | Exfil - `nslookup.exe` burst `*.haz4rdw4re.io`, `*.haz4f6dwire.lo` with Base64 subdomains |

**Root Cause:** Phishing → PowerShell C2 (PID 3728) → AD Recon via PowerView → Financial share access → Bulk staging via Robocopy → DNS tunneling exfiltration.

**IOCs:**
- `C:\Users\michael.ascott\Downloads\PowerView.ps1`
- `C:\Users\michael.ascott\downloads\exfiltration\`
- `2.tcp.ngrok.io:19282`
- `haz4rdw4re.io`, `haz4f6dwire.lo`
- `win-3450`, `FILESRV-01\SSF-FinancialRecords`

**MITRE ATT&CK:** T1566, T1018, T1083, T1039, T1005, T1041, T1071.004, T1048.003, T1070

**Response Actions:**
1. Isolate win-3450
2. Disable user + reset creds
3. Block ngrok & haz4rdw4re domains
4. Audit FILESRV-01 access 10:57-10:58
5. Collect exfiltration folder for forensics

**Screenshots:** See `/screenshots/02-repossessed-win3450/`

---

## Tools Used
- TryHackMe SOC Simulator (Splunk, Sysmon, ProcessCreate logs)
- Splunk SPL for hunting: `index=* host=win-3450 powershell` 
- MITRE ATT&CK mapping

## What I Learned
Correlating same PID (3728) across 7 alerts to build a single incident instead of closing alerts in isolation. DNS exfil via nslookup with base64 subdomains is easy to miss if you only look at severity.
