## Executive Summary

### Investigation Overview
This investigation focused on analyzing a security breach at **FinTrust Bank**, where **unusual outbound network activity** was detected. The attack was traced back to a **WinRAR vulnerability (CVE-2023-38831)**, which was exploited to execute malicious scripts, exfiltrate sensitive data, and erase forensic traces.

### Key Findings
1. **Initial Access:**
   - The attacker delivered a **malicious `.RAR` archive** (`SANS SEC401.rar`) via **Telegram Desktop**.
   - The archive contained an **obfuscated script disguised as a `.PDF` file**, tricking the user into execution.

2. **Execution & Persistence:**
   - **PowerShell scripts (`run.ps1`, `eventlogs.ps1`)** were executed with administrative privileges using **execution policy bypass (`-NOP -EP Bypass`)**.
   - The attacker may have used **scheduled tasks** for persistence (further analysis required).

3. **Defense Evasion:**
   - The script `Eventlogs.ps1` was responsible for **clearing Windows Event Logs** (`Event ID 1102`) to erase traces.
   - **Event ID 403** confirmed the execution of `Eventlogs.ps1` at the exact moment the logs were cleared.

4. **Discovery & Collection:**
   - The attacker **scanned the internal network** using `run.ps1`, identifying live hosts within the **192.168.1.x subnet**.
   - The scan results were stored in a **temporary file (`BL4356.txt`)** before being staged for exfiltration.

5. **Exfiltration:**
   - **Data was encoded in Base64** and sent to an attacker-controlled server at `http://192.168.1.5:8000/`.
   - The HTTP request contained encoded host scan results, facilitating further exploitation.

### MITRE ATT&CK Techniques Used
- **Initial Access:** T1204 (User Execution via Telegram & WinRAR Exploit)
- **Execution:** T1059.001 (PowerShell Execution via `run.ps1`)
- **Defense Evasion:** T1070.001 (Clearing Event Logs via `eventlogs.ps1`)
- **Discovery:** T1046 (Network Scanning via `run.ps1`)
- **Exfiltration:** T1041 (Exfiltration Over HTTP via `BL4356.txt`)

### Conclusion & Recommendations
This attack demonstrates a **well-orchestrated intrusion leveraging a known vulnerability (CVE-2023-38831)** to gain execution on the victim’s system, conduct **internal reconnaissance**, and exfiltrate **sensitive network data**. The attacker effectively used **PowerShell-based obfuscation** and **log tampering** to evade detection.

#### Recommended Actions:

1. **Patch WinRAR to version 6.23** to prevent exploitation of **CVE-2023-38831**.
2. **Restrict PowerShell execution policies** and monitor **script-based execution logs (Event ID 403, 4688)**.
3. **Implement network segmentation** to prevent unauthorized lateral movement.
4. **Enhance logging and monitoring** to detect suspicious script executions and unauthorized outbound connections.
5. **Educate users on phishing and social engineering techniques** to prevent opening of **malicious archives**.
6. **Remove malicious files from the system** to prevent further execution:
    - **SANS SEC401.pdf .cmd** → `C:\cases\SpottedInTheWild\SANS SEC401.pdf .cmd`
    - **amanwhogetsnorest.jpg** → `C:\Windows\Temp\amanwhogetsnorest.jpg`
    - **Eventlogs.ps1** → `C:\Windows\Temp\Eventlogs.ps1`
    - **run.bat** → `C:\Windows\Temp\run.bat`
    - **run.ps1** → `C:\Windows\Temp\run.ps1`
    - **z.ps1** → `C:\Windows\Temp\z.ps1`
    - **BL4356.txt** → `%UserProfile%\AppData\Local\Temp\BL4356.txt`

#### Additional Recommendations:

7. **Disable BITS (Background Intelligent Transfer Service) if not needed** – This attack used BITS to stealthily download files. Regularly audit and restrict BITS transfers where necessary.
8. **Monitor scheduled tasks (Event ID 4698, 4702, 106)** – The attacker created a **scheduled task** (`whoisthebaba`) for persistence. Review and remove unauthorized tasks using:
    
    ```
    schtasks /delete /tn "whoisthebaba" /f
    ```
    
9. **Analyze registry modifications** – Some malware may modify registry keys for persistence. Investigate `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` for suspicious entries.
10. **Deploy endpoint detection and response (EDR) tools** – Utilize advanced security tools to detect and respond to similar attacks in the future.
11. **Perform a full forensic analysis** – If this attack was part of a larger compromise, conduct a **full disk and memory analysis** to detect additional artifacts or backdoors.
12. **Audit firewall and proxy logs** – Identify any unusual connections, particularly **outbound traffic to 172.18.35.10:8000**, which was used for file exfiltration.

By implementing these actions, the attack vector is mitigated, persistence is removed, and further exploitation is prevented.