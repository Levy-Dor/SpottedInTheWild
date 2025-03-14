# **Introduction**

## **The Investigator**

My name is **Dor Levy**, and I specialize in **Digital Forensics, Incident Response, Threat Hunting, and Malware Analysis**. I have experience conducting **endpoint, memory, and network forensics**, as well as handling complex security incidents. I have worked with leading forensic tools and security solutions such as **Security Information and Event Management (SIEM), Endpoint Detection and Response (EDR), and various incident response frameworks** to enhance detection and response capabilities.

I have collaborated with **Security Operations Center (SOC) teams** as part of a **Blue Team**, developing **custom scripts** to optimize forensic investigations and presenting **detailed forensic findings** to senior management.

The outcome of this task is a **comprehensive and detailed Incident Response (IR) report**, which includes all aspects of the investigation.
### **Scenario Overview**

This investigation was conducted in response to a **security breach at FinTrust Bank**, where anomalous **outbound network activity** was detected. The initial forensic analysis suggested a potential compromise linked to an **exploited vulnerability in WinRAR (CVE-2023-38831)**, which enabled attackers to gain unauthorized access, execute malicious scripts, and exfiltrate sensitive data.

### **Forensic Lab Setup**

All forensic investigations I conduct take place within a **custom-built forensic lab** that I established independently. This lab was created using **VMware**, where I deployed a **Windows 10 environment** and installed a wide range of forensic and malware analysis tools to facilitate detailed investigations. This setup allows for controlled analysis of malware, endpoint artifacts, and memory dumps while ensuring the integrity of the evidence.

The following forensic tools are installed in my lab (this is not an exhaustive list, but these are the primary tools I use):

- **Arsenal Image Mounter** – Mounting forensic disk images, including Volume Shadow Copies.
- **CMDWatcher** – Monitoring command-line execution for forensic analysis.
- **dnSpy** – .NET debugger and decompiler used for analyzing malware.
- **KAPE (Kroll Artifact Parser and Extractor)** – Collecting and processing key forensic artifacts.
- **Eric Zimmerman Tools (EZTools, net6)** – A suite of forensic utilities for event log parsing, MFT analysis, and registry forensics.
- **NirSoft Tools** – A suite of utilities for extracting system and network-related artifacts.
- **PEStudio** – Static analysis tool for inspecting executables and malware.
- **SQLite** – Database analysis tool used for forensic investigations.
- **Sysinternals Suite** – System monitoring and analysis tools (e.g., Process Explorer, Autoruns, Strings).
- **Volatility3** – Memory forensics framework for extracting and analyzing volatile data.
- **010 Editor** – Hex and binary file editor used for deep file analysis.
- **Wireshark** – Network protocol analyzer used for traffic inspection and forensic investigations.
- **FTK Imager** – Disk imaging and live analysis tool for examining evidence.

### **Investigation Approach**

This investigation incorporated a combination of **endpoint forensics** and **malware analysis** using both **static and dynamic techniques**. The following methodologies were employed:

- **Endpoint Forensics:**
  - Analyzing the **Windows Registry, Event Logs, Master File Table (MFT), and USN Journal** to reconstruct the attack timeline.
  - Identifying **persistence mechanisms**, executed scripts, and indicators of log tampering.

- **Malware Analysis:**
  - **Static Analysis:** Inspecting file hashes, metadata, and embedded strings for indicators of malicious behavior.
  - **Dynamic Analysis:** Executing scripts and analyzing behavioral patterns to identify potential network connections, data exfiltration, and log manipulation.

#### **Tools Used in This Investigation**

To conduct this forensic analysis, I utilized a diverse set of **industry-standard forensic and malware analysis tools**, including:

- **Sysinternals Suite** – System monitoring and analysis tools (e.g., Process Explorer, Autoruns, Strings).
- **EZTools** – A collection of forensic tools, including **EvtxECmd** for event log parsing.
- **Arsenal Image Mounter** – Mounting forensic disk images, including Volume Shadow Copies.
- **KAPE (Kroll Artifact Parser and Extractor)** – Collecting and processing key forensic artifacts.
- **NirSoft Tools** – Extracting system and network-related artifacts.
- **RECmd & MFTECmd** – Parsing registry hives and Master File Table (MFT) to analyze file activity and timestamps.
- **CyberChef** – Decoding obfuscated scripts and Base64-encoded exfiltrated data.