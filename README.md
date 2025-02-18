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

| MDM Setting | Recommended Action |
|-------------|--------------------|
| **Browser/AllowSmartScreen** | **1 – Turns on SmartScreen.** |
| `./Device/Vendor/MSFT/Policy/Config/Browser/AllowSmartScreen` |  |
| **Browser/PreventSmartScreenPromptOverride** | **1 – Blocks users from ignoring website warnings.** |
| `./Device/Vendor/MSFT/Policy/Config/Browser/PreventSmartScreenPromptOverride` |  |
| **Browser/PreventSmartScreenPromptOverrideForFiles** | **1 – Blocks users from ignoring file download warnings.** |
| `./Device/Vendor/MSFT/Policy/Config/Browser/PreventSmartScreenPromptOverrideForFiles` |  |
| **SmartScreen/EnableSmartScreenInShell** | **1 – Enables SmartScreen in Windows Explorer.** |
| `./Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableSmartScreenInShell` |  |
| **SmartScreen/PreventOverrideForFilesInShell** | **1 – Blocks users from bypassing file warnings.** |
| `./Device/Vendor/MSFT/Policy/Config/SmartScreen/PreventOverrideForFilesInShell` |  |

### Related Browser Policy CSP

#### Key Policy Categories & Functions
##### Security & Privacy Controls
- **AllowSmartScreen** – Enables or disables Microsoft Defender SmartScreen, which warns users about phishing sites and malicious downloads.
- **PreventSmartScreenPromptOverride** – Prevents users from bypassing SmartScreen security warnings for malicious websites.
- **PreventSmartScreenPromptOverrideForFiles** – Blocks users from ignoring SmartScreen warnings on file downloads.
- **PreventCertErrorOverrides** – Restricts users from overriding SSL/TLS certificate errors.
- **AllowDoNotTrack** – Enables "Do Not Track" requests to websites.
- **AllowCookies** – Configures whether all, third-party, or no cookies are allowed.

##### User Experience & UI Customization
- **AllowAddressBarDropdown** – Controls whether search suggestions appear in the address bar.
- **AllowAutofill** – Manages Autofill settings for form fields.
- **AllowBrowser** – Determines whether Edge can be used as a browser. *(Deprecated)*
- **AllowSearchEngineCustomization** – Allows users to customize their default search engine.
- **ConfigureHomeButton** – Locks down or customizes the Home button behavior.
- **AllowWebContentOnNewTabPage** – Configures whether the New Tab Page loads with content or remains blank.

##### Performance & Startup Settings
- **AllowPrelaunch** – Enables Edge pre-launch at Windows startup, reducing load times.
- **AllowTabPreloading** – Allows Edge to preload the Start and New Tab pages for faster access.
- **ConfigureOpenMicrosoftEdgeWith** – Controls how Edge starts (New Tab, Start Page, or custom URL).
- **PreventFirstRunPage** – Stops the Microsoft Edge First Run page from appearing at launch.

##### Extensions & Add-ons
- **AllowExtensions** – Controls whether users can install browser extensions.
- **PreventTurningOffRequiredExtensions** – Prevents users from disabling preinstalled enterprise extensions.
- **AllowSideloadingOfExtensions** – Allows or blocks sideloading of extensions outside the Microsoft Store.

##### Enterprise & Compatibility Settings
- **EnterpriseModeSiteList** – Configures Enterprise Mode, forcing certain websites to open in Internet Explorer 11 for compatibility.
- **SendIntranetTrafficToInternetExplorer** – Forces intranet sites to open in IE11.
- **SyncFavoritesBetweenIEAndMicrosoftEdge** – Synchronizes bookmarks between IE and Edge.

##### Miscellaneous Settings
- **AllowPrinting** – Controls whether users can print web content.
- **AllowDeveloperTools** – Enables or disables access to F12 Developer Tools.
- **PreventAccessToAboutFlagsInMicrosoftEdge** – Blocks users from accessing about:flags settings.
- **LockdownFavorites** – Prevents users from editing or removing preconfigured Favorites.
- **ClearBrowsingDataOnExit** – Automatically deletes browsing history when Edge is closed.

### Related SmartScreen Policy CSP

#### Application Installation Control
- **EnableAppInstallControl**
  - Restricts or allows app installations from sources other than the Microsoft Store.
  - Requires `SmartScreen/EnableSmartScreenInShell` and `SmartScreen/PreventOverrideForFilesInShell` to block offline installations.
  - **Options:**
    - `0` (Default) – Allows apps from any source.
    - `1` – Only allows apps from the Microsoft Store.
    - `2` – Notifies users about comparable apps in the Store.
    - `3` – Warns users before installing apps outside the Store.

#### Enabling SmartScreen for Windows
- **EnableSmartScreenInShell**
  - Enables or disables Windows Defender SmartScreen for Windows Explorer.
  - **Default:** Enabled (`1`) – Protects users from downloading or running suspicious files.

#### Preventing User Overrides for SmartScreen Warnings
- **PreventOverrideForFilesInShell**
  - Controls whether users can bypass SmartScreen warnings and run files flagged as malicious.
  - **Default:** `0` (Users can override warnings).
  - `1` (Enabled) – Users cannot bypass SmartScreen warnings.
 
# Network Protection in Microsoft Defender for Endpoint

Microsoft Defender for Endpoint (MDE) includes **Network Protection**, a security feature that helps prevent users from accessing malicious or suspicious websites and IPs. It is part of attack surface reduction and works by blocking outbound HTTP(S) connections to domains with a low reputation or those known for cyberattacks.

## Key Features of Network Protection

### Preventing Access to Malicious Sites
- Blocks access to websites hosting phishing scams, malware, and exploits.
- Works at the **operating system level**, expanding SmartScreen protection beyond just Microsoft Edge.
- Provides visibility and blocking of **indicators of compromise (IOCs)** in endpoint detection and response (EDR).

### Coverage Across Different Applications

| Feature | Microsoft Edge | Non-Microsoft Browsers | Non-Browser Apps (e.g., PowerShell) |
|---------|---------------|---------------------|------------------|
| Web Threat Protection | Requires SmartScreen | Requires Network Protection (Block Mode) | Requires Network Protection (Block Mode) |
| Custom Indicators (Block/Allow Lists) | Requires SmartScreen | Requires Network Protection (Block Mode) | Requires Network Protection (Block Mode) |
| Web Content Filtering | Requires SmartScreen | Requires Network Protection (Block Mode) | Not Supported |

## Requirements for Network Protection
- Requires **Microsoft Defender Antivirus** with:
  - Real-time protection, cloud-delivered protection, and behavior monitoring enabled.
- **Windows Server 2012 R2 & 2016**: Needs modern unified agent (version 4.18.2001.x.x or newer).

## Why Network Protection is Important
- Prevents malware infections by blocking **Command and Control (C2) servers** used in ransomware and botnets.
- Enforces security policies, including:
  - Blocking unsanctioned services (**Microsoft Defender for Cloud Apps**).
  - Web content filtering (**Blocking access to certain website categories**).
- Protects against phishing by integrating **SmartScreen intelligence**.

## Network Protection Blocking & Notifications

| Scenario | Behavior |
|----------|----------|
| Safe Website | No block, access allowed |
| Unknown Reputation | User sees a warning (toast notification), can "Unblock" the site for 24 hours or submit a request for access. |
| Malicious URL/IP | Access fully blocked, only admin overrides possible. |

- Admins can allow "unblock" for up to 24 hours for certain URLs.
- Notifications categories:
  - **Phishing** (SmartScreen)
  - **Malicious Content** (SmartScreen)
  - **Command & Control (C2)** (SmartScreen)
  - **Custom Block Lists & Policies** (Admin-configured)

## Enabling & Configuring Network Protection

### 1. Group Policy (GPO)
- **Path:** `Computer Configuration > Administrative Templates > Windows Defender Antivirus > Network Inspection System`
- **Setting:** Convert warn verdict to block → **Enabled**

### 2. PowerShell Command:
```powershell
Set-MpPreference -EnableNetworkProtection Enabled
```

### 3. MDM CSP (Intune)
- Configured via **Microsoft Defender for Endpoint portal**.
- Steps:
  1. Sign into the **Microsoft Intune admin center**.
  2. Go to **Endpoint security > Security baselines > Microsoft Defender for Endpoint Baseline**.
  3. Select **Create a profile**, provide a name, then **Next**.
  4. In **Configuration settings**, navigate to **Attack Surface Reduction Rules** > **Enable network protection** and select **Block, Enable, or Audit**. Then click **Next**.
  5. Select appropriate **Scope tags** and **Assignments** as needed.
  6. Review and click **Create**.

### 4. Registry Settings
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1
```

## Monitoring & Hunting for Network Protection Events
- **Audit Mode**: Logs blocked connections without enforcing a block.
- **Advanced Hunting Queries (Defender for Endpoint):**
```kusto
DeviceEvents
| where ActionType in ('ExploitGuardNetworkProtectionAudited','ExploitGuardNetworkProtectionBlocked')
```

- **Event Viewer Logs:**
  - **ID 1125** → Audit Mode triggered
  - **ID 1126** → Block Mode triggered

## Additional Considerations

### Command & Control (C2) Detection & Blocking
- Breaks connection to hacker-controlled servers used for:
  - **Stealing data**
  - **Controlling botnets**
  - **Spreading malware**

### Network Protection and TCP Handshake
- Blocks traffic **after** the **TCP three-way handshake** completes.
- Logs may initially show "ConnectionSuccess" even if a site is later blocked.

## Optimizing Network Protection Performance

### Enable Asynchronous Inspection
```powershell
Set-MpPreference -AllowSwitchToAsyncInspection $true
```

### Disable QUIC Protocol (to ensure traffic inspection):
- **Edge:** `edge://flags/#enable-quic` → Disabled
- **Chrome:** `chrome://flags/#enable-quic` → Disabled

## Recommendations
✔ **Enable Network Protection in Block Mode** to enforce security policies.
✔ **Use Advanced Hunting in Defender for Endpoint** to monitor network events.
✔ **Test in Audit Mode** before enforcing blocks to prevent unintended disruptions.
✔ **Disable QUIC Protocol** to ensure all web traffic is inspected.
✔ **Use Custom Indicators** to define organization-specific block/allow lists.

---

## Testing SmartScreen Implementations
1. **Windows Defender SmartScreen Connectivity Test:** [GitHub - Microsoft Connectivity Tester](https://github.com/nsacyber/HTTP-Connectivity-Tester)
2. **Microsoft Defender for Endpoint Demonstration Scenarios:**
   - [PUA Demonstration](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/pua-protection)
   - [URL Reputation Demonstration](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/smartscreen-url-reputation)

---

This document provides an overview of **Network Protection in Microsoft Defender for Endpoint**, its configurations, and best practices for organizations. For further details, visit **Microsoft Learn**.

