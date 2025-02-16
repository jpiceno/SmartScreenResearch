# Microsoft Defender SmartScreen Overview

Microsoft Defender SmartScreen is a security feature in Windows 10, Windows 11, and Microsoft Edge designed to protect users from phishing, malware websites, and malicious downloads. It enhances security by analyzing webpages, checking URLs against a database of reported malicious sites, and evaluating downloaded files based on their reputation.

## Key Features & Benefits
- **Anti-Phishing & Anti-Malware Protection** – Warns users about potentially dangerous websites and downloads.
- **Reputation-Based Protection** – Evaluates websites and applications to determine their safety before allowing access.
- **OS Integration** – Works across Windows applications, including third-party browsers and email clients.
- **Advanced Heuristics & Diagnostics** – Uses AI-driven learning to stay updated on emerging threats.
- **Enterprise Management** – Can be controlled via Group Policy and Microsoft Intune for centralized security management.
- **Blocking Potentially Unwanted Applications (PUAs)** – Prevents users from accessing harmful applications in Microsoft Edge (Chromium-based).

### Limitations:
- SmartScreen only protects against threats from the internet and does not block malicious files from internal network shares (UNC paths, SMB/CIFS).

---

## Available Microsoft Defender SmartScreen Settings

Microsoft Defender SmartScreen helps protect users from malicious content by warning or blocking access to unsafe websites and files. It can be managed using **Group Policy, Microsoft Intune, and Mobile Device Management (MDM)**.

### MDM (Intune) Settings
Organizations using Microsoft Intune can configure SmartScreen with MDM policies.

| Setting | Function |
|---------|----------|
| AllowSmartScreen | Enables SmartScreen protection. |
| EnableAppInstallControl | Controls app installations from external sources. |
| EnableSmartScreenInShell | Enables SmartScreen protection in Windows Explorer. |
| PreventOverrideForFilesInShell | Prevents users from bypassing warnings for malicious files. |
| PreventSmartScreenPromptOverride | Blocks users from bypassing website warnings. |
| PreventSmartScreenPromptOverrideForFiles | Blocks users from downloading unsafe files. |

### Recommended Settings for Organizations
Microsoft recommends blocking high-risk interactions instead of just showing warnings.

| Group Policy Setting | Recommended Action |
|----------------------|--------------------|
| Configure Windows Defender SmartScreen (Microsoft Edge) | Enable – Turns on SmartScreen protection. |
| Prevent bypassing Windows Defender SmartScreen prompts for sites | Enable – Blocks users from overriding security warnings. |
| Configure Windows Defender SmartScreen (Explorer) | Enable with Warn and Prevent Bypass – Ensures users can't bypass malicious file warnings. |

---

## Enhanced Phishing Protection in Microsoft Defender SmartScreen

Enhanced Phishing Protection in Microsoft Defender SmartScreen helps safeguard **Microsoft work or school passwords** against phishing attacks and unsafe usage in **Windows 11 (22H2)**.

### Key Benefits
1. **Anti-Phishing Protection:**
   - Detects phishing sites and credential harvesting attacks.
   - Warns users when they enter passwords into malicious sites.
2. **OS-Level Security Integration:**
   - Works across all browsers and apps, not just Microsoft Edge.
   - Detects unsafe password entry in any application.
3. **Microsoft Security Suite Integration:**
   - Provides detailed telemetry data for Microsoft Defender for Endpoint (MDE).
   - Helps organizations track phishing attempts and password security risks.

### Configuration & Policy Settings

| Setting | Description | Recommendation |
|---------|------------|---------------|
| Automatic Data Collection | Collects additional information (like displayed content and memory usage) when passwords are entered on suspicious sites. | Enable |
| Service Enabled | Enables audit mode to capture password entry events but does not show user notifications. | Enable |
| Notify Malicious | Warns users when they enter work/school passwords on phishing or insecure sites. | Enable |
| Notify Password Reuse | Warns users when they reuse their work or school password across multiple sites or apps. | Enable |
| Notify Unsafe App | Warns users when they store passwords in Notepad, Word, or Microsoft 365 apps. | Enable |

### Deployment Methods
Organizations can apply these settings using:
- **Microsoft Intune** (Settings Catalog under "SmartScreen > Enhanced Phishing Protection")
- **Group Policy (GPO)**
- **Configuration Service Provider (CSP)**

---

## Network Protection in Microsoft Defender for Endpoint

Network Protection is a security feature in **Microsoft Defender for Endpoint (MDE)** that helps prevent users from accessing malicious or suspicious websites and IPs.

### Key Features
- **Prevents access to malicious sites**
- **Works at the OS level**, expanding SmartScreen protection beyond just Microsoft Edge.
- **Provides visibility and blocking of Indicators of Compromise (IOCs) in endpoint detection and response (EDR).**

### Coverage Across Different Applications
| Feature | Microsoft Edge | Non-Microsoft Browsers | Non-Browser Apps (e.g., PowerShell) |
|---------|---------------|---------------------|------------------|
| Web Threat Protection | Requires SmartScreen | Requires Network Protection (Block Mode) | Requires Network Protection (Block Mode) |
| Custom Indicators (Block/Allow Lists) | Requires SmartScreen | Requires Network Protection (Block Mode) | Requires Network Protection (Block Mode) |
| Web Content Filtering | Requires SmartScreen | Requires Network Protection (Block Mode) | Not Supported |

### Enabling & Configuring Network Protection
Network Protection can be enabled using:
1. **Group Policy (GPO)**
   - Path: `Computer Configuration > Administrative Templates > Windows Defender Antivirus > Network Inspection System`
   - Setting: Convert warn verdict to block → Enabled
2. **PowerShell Command:**
   ```powershell
   Set-MpPreference -EnableNetworkProtection Enabled
   ```
3. **MDM CSP (Intune):**
   - Configured via **Microsoft Defender for Endpoint portal**.
4. **Registry Settings:**
   - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
   - Set `EnableNetworkProtection` to **1 (Enabled)**

### Optimizing Network Protection Performance
```powershell
Set-MpPreference -AllowSwitchToAsyncInspection $true
```
- **Disable QUIC Protocol (ensures traffic inspection):**
  - Edge: `edge://flags/#enable-quic` → Disabled
  - Chrome: `chrome://flags/#enable-quic` → Disabled

### Recommendations
✔ Enable **Network Protection in Block Mode** to enforce security policies.
✔ Use **Advanced Hunting in Defender for Endpoint** to monitor network events.
✔ Test in **Audit Mode** before enforcing blocks to prevent unintended disruptions.
✔ **Disable QUIC Protocol** to ensure all web traffic is inspected.
✔ Use **Custom Indicators** to define organization-specific block/allow lists.

---

## Testing Smart Screen Implementations
1. **Windows Defender SmartScreen Connectivity Test:** [GitHub - Microsoft Connectivity Tester](https://github.com/nsacyber/HTTP-Connectivity-Tester)
2. **Microsoft Defender for Endpoint Demonstration Scenarios:**
   - [PUA Demonstration](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/pua-protection)
   - [URL Reputation Demonstration](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/smartscreen-url-reputation)

---

This document provides an overview of Microsoft Defender SmartScreen, its settings, configurations, and best practices for organizations. For further details, visit the **Microsoft Learn** documentation.
