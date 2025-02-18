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
