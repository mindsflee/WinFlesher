# WinFlesher: Attack Surface Security Framework

<p align="center">
  <img src="https://github.com/mindsflee/WinFlesher/blob/main/Assets/Logo/winflesher_logo.png" alt="WinFlesher Logo" width="200" />
</p>

> *WinFlesher: Like PingCastle went out for drinks with Bloodhound, and they actually decided to get some work done. 🍷*

**WinFlesher** is an advanced attack surface security assessment framework designed to analyze, evaluate, and report on security postures, attack paths, and remediation strategies in complex environments.

Developed for security professionals and cybersecurity auditors, WinFlesher automates vulnerability discovery and critical path correlation within Active Directory and local infrastructures.

---

## Features Overview

WinFlesher offers a modular, telemetry-based approach to risk management:

*   **Automated Discovery:** Real-time detection of host configurations, services, scheduled tasks, firewalls, and LSA configurations.
*   **Active Directory Analysis:** In-depth analysis of domains, trusts, group privileges, and users with exposed SPNs.
*   **Attack Paths Engine:** Automatic correlation between vulnerabilities and impact, identifying paths to *Domain Compromise*, *Privilege Escalation*, and *Lateral Movement*.
*   **Remediation Support:** Integrated practical guides and resolution scripts for each detected vulnerability.
*   **Modern GUI:** Dedicated graphical interface for rapid management and an intuitive visualization of the security score.

---

## Installation

The quickest way to get started is to download the entire repository as a ZIP archive and extract it locally:

1.  Download the repository by clicking the **"Download ZIP"** button on the main GitHub page.
2.  Extract the ZIP file to a secure folder (e.g., `C:\Tools\WinFlesher`).
3.  **Note:** Ensure that PowerShell script execution is enabled on your system:
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    ```

---

## Required Modules

To fully leverage WinFlesher's capabilities (especially for the Active Directory and Cloud components), ensure you have the following modules installed:

*   **Active Directory:**
    ```powershell
     Install-WindowsFeature RSAT-AD-PowerShell
    ```
*   **Microsoft Graph (for Entra ID):**
    ```powershell
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser
    ```

---

## How to Run WinFlesher

To start the framework, open a PowerShell console (running as Administrator is recommended for full telemetry gathering), navigate to the root directory, and simply execute:

```powershell
. .\Invoke-winflesher.ps1
