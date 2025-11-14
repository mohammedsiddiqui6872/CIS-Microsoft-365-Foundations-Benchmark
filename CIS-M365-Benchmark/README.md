# CIS Microsoft 365 Foundations Benchmark v5.0.0 - Automated Compliance Checker

[![PowerShell Gallery Version](https://img.shields.io/badge/Version-2.4.0-blue.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v5.0.0-orange.svg)](https://www.cisecurity.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg)](https://buymeacoffee.com/mohammedsiddiqui)

A comprehensive PowerShell module that audits your Microsoft 365 environment against **all 130 CIS Microsoft 365 Foundations Benchmark v5.0.0 controls** and generates detailed HTML and CSV compliance reports with zero false positives.

## 🎉 What's New in v2.4.0

**Critical False Positive Fixes - Batch 2 (Complete)**

This release fixes **11 additional controls** to eliminate false positives and improve accuracy:

✅ **Enhanced Validation**: 10 controls now perform comprehensive validation instead of simple property existence checks
✅ **Fixed API Issues**: Corrected hashtable property access, cmdlet selection, and API endpoint usage
✅ **Improved Logic**: Fixed contradictory logic and hardcoded values across multiple controls
✅ **CA Policy Enhancements**: Added report-only mode detection and exclusion warnings

**Key Fixes:**
- 5.2.2.4: Admin sign-in frequency validates actual value (≤4 hours)
- 5.2.2.10/11: MFA registration & Intune enrollment validate requirements
- 5.2.3.6: System-preferred MFA fixed beta API access
- 6.5.3: OWA storage providers checks all policies
- 8.2.1/8.4.1: Teams external domains & app policies fixed
- 7.2.4/7.3.4: SharePoint/OneDrive sharing & custom scripts improved
- 5.2.2.3: Legacy auth enhanced client type validation
- CA Policies: Report-only detection + exclusion warnings added

[View Full Changelog](CHANGELOG.md) | [View v2.3.9 Fixes](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/blob/main/CHANGELOG.md#239---previous-version)

## 🚀 Features

- ✅ **130 Automated Compliance Checks** across all M365 services
- 🎯 **Zero False Positives** - v2.4.0 eliminates false positives with comprehensive validation
- 📊 **68% Fully Automated** - Most checks run automatically via Microsoft Graph API
- 📈 **Zero-Parameter Authentication** - New `Connect-CISBenchmark` command for easy setup
- 📄 **Dual Report Format** - Professional HTML and CSV reports with floating action buttons
- 🎯 **Profile-based Filtering** - Check L1, L2, or All controls
- 🔐 **Secure Authentication** - Modern OAuth 2.0 with persistent token caching
- 🛡️ **No Data Modification** - Read-only assessment, no changes to your environment
- 📝 **Actionable Remediation** - Each failed check includes specific remediation steps
- ⚡ **PowerShell 5.1 & 7+ Compatible** - Works on Windows PowerShell and PowerShell Core

## 📋 What Gets Checked

The script performs comprehensive checks across **9 major sections**:

### Section 1: Microsoft 365 Admin Center (8 controls)
- ✅ Administrative account configurations
- ✅ Global admin count validation
- ✅ Public group management
- ✅ Shared mailbox security
- ✅ Password expiration policies
- ⚠️ Idle session timeouts (Manual)
- ⚠️ Calendar sharing settings (Manual)
- ⚠️ User-owned apps restrictions (Manual)

### Section 2: Microsoft 365 Defender (14 controls)
- ✅ Safe Links for Office applications
- ✅ Common attachment type filters
- ✅ Malware notification settings
- ✅ Safe Attachments policies
- ✅ SPF, DKIM, and DMARC records
- ✅ Anti-phishing policies
- ✅ Connection filter configurations
- ✅ Zero-hour auto purge settings
- ⚠️ Priority account protection (Manual)
- ⚠️ Microsoft Defender for Cloud Apps (Manual)

### Section 3: Microsoft Purview (3 controls)
- ✅ Audit log search enabled
- ✅ DLP policies enabled (Exchange & Teams)
- ⚠️ Sensitivity label policies (Manual)

### Section 4: Microsoft Intune Admin Center (2 controls)
- ✅ Device compliance policy settings
- ✅ Personal device enrollment restrictions

### Section 5: Microsoft Entra Admin Center (41 controls)

#### Identity & Access (5.1.x - 13 controls)
- ✅ Cloud-only administrative accounts
- ✅ Emergency access account configuration
- ✅ Global admin count (2-4 admins)
- ✅ Third-party app registration restrictions
- ✅ Tenant creation restrictions
- ✅ Entra admin center access controls
- ✅ Dynamic groups for guest users
- ✅ User consent settings
- ✅ Guest user access restrictions
- ⚠️ Company branding settings (Manual)
- ⚠️ LinkedIn account connections (Manual)

#### Conditional Access (5.2.2.x - 12 controls)
- ✅ MFA for administrative roles
- ✅ MFA for all users
- ✅ Block legacy authentication
- ✅ Admin sign-in frequency
- ✅ User risk policies
- ✅ Sign-in risk policies
- ✅ Managed device requirements
- ✅ Managed device for MFA registration
- ✅ Intune enrollment sign-in frequency
- ⚠️ Phishing-resistant MFA (Manual)
- ⚠️ Device code flow blocking (Manual)

#### Authentication Methods (5.2.3.x - 6 controls)
- ✅ Microsoft Authenticator MFA fatigue protection
- ✅ Custom banned password lists
- ✅ All users MFA capable
- ✅ Weak authentication methods disabled (SMS/Voice)
- ✅ System-preferred MFA enabled
- ⚠️ On-premises password protection (Manual - Hybrid only)

#### Password Reset (5.2.4.x - 1 control)
- ✅ Self-service password reset enabled

#### Identity Governance (5.3.x - 5 controls)
- ✅ Privileged Identity Management (PIM) configured
- ✅ Access reviews for guest users
- ✅ Access reviews for privileged roles
- ✅ Global Administrator approval requirements
- ✅ Privileged Role Administrator approval requirements

### Section 6: Exchange Admin Center (14 controls)
- ✅ Organization audit enabled
- ✅ Mailbox audit configurations
- ✅ Mailbox audit bypass checks
- ✅ Mail forwarding restrictions
- ✅ Transport rule whitelisting
- ✅ External email identification
- ✅ Outlook add-in restrictions
- ✅ Modern authentication enabled
- ✅ MailTips enabled
- ✅ OWA storage provider restrictions
- ✅ SMTP AUTH disabled

### Section 7: SharePoint Admin Center (14 controls)
- ✅ Modern authentication requirements
- ✅ Azure AD B2B integration
- ✅ External content sharing restrictions
- ✅ OneDrive sharing restrictions
- ✅ Guest re-sharing prevention
- ✅ Domain allow/deny lists
- ✅ Link sharing configurations
- ✅ Guest link expiration
- ✅ Email verification requirements
- ✅ Default link permissions
- ✅ Infected file download blocking
- ✅ OneDrive sync restrictions
- ✅ Custom script execution restrictions

### Section 8: Microsoft Teams Admin Center (13 controls)
- ✅ External file sharing restrictions
- ✅ Channel email settings
- ✅ External domain restrictions
- ✅ Unmanaged Teams user blocking
- ✅ External conversation initiation
- ✅ Skype communication settings
- ✅ App permission policies
- ✅ Anonymous meeting join settings
- ✅ Lobby bypass configurations
- ✅ Meeting chat restrictions
- ✅ Presenter role limitations
- ✅ External control restrictions
- ✅ Meeting recording defaults

### Section 9: Microsoft Fabric (Power BI) (11 controls)
- ⚠️ Guest user access restrictions (Manual)
- ⚠️ External user invitations (Manual)
- ⚠️ Content sharing restrictions (Manual)
- ⚠️ Publish to web restrictions (Manual)
- ⚠️ R and Python visual restrictions (Manual)
- ⚠️ Sensitivity labels configuration (Manual)
- ⚠️ Shareable link restrictions (Manual)
- ⚠️ External data sharing (Manual)
- ⚠️ ResourceKey authentication blocking (Manual)

*Note: Power BI checks require the Power BI Admin module and additional permissions*

## 📊 Automation Coverage

| Category | Total Controls | Automated | Manual | Coverage |
|----------|---------------|-----------|--------|----------|
| **Section 1: M365 Admin** | 8 | 4 | 4 | 50% |
| **Section 2: M365 Defender** | 14 | 10 | 4 | 71% |
| **Section 3: Purview** | 3 | 2 | 1 | 67% |
| **Section 4: Intune** | 2 | 2 | 0 | 100% |
| **Section 5: Entra ID** | 41 | 32 | 9 | 78% |
| **Section 6: Exchange** | 14 | 13 | 1 | 93% |
| **Section 7: SharePoint** | 14 | 13 | 1 | 93% |
| **Section 8: Teams** | 13 | 13 | 0 | 100% |
| **Section 9: Power BI** | 11 | 0 | 11 | 0% |
| **TOTAL** | **130** | **89** | **41** | **68%** |

## 📦 Installation

### Option 1: Install from PowerShell Gallery (Recommended)

```powershell
# Install the latest version (v2.4.0) from PowerShell Gallery
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser

# Update to latest version if you have an older version installed
Update-Module -Name CIS-M365-Benchmark -Force

# Verify installation
Get-Module -ListAvailable CIS-M365-Benchmark
```

**Note**: The module automatically detects and installs required dependencies on first run. You can also manually install them:

```powershell
# Install required dependencies (optional - auto-installed if missing)
Install-Module -Name Microsoft.Graph -Scope CurrentUser -MinimumVersion 2.0 -Force
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force
Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force
Install-Module -Name MSOnline -Scope CurrentUser -Force  # Legacy module (optional)
```

### 💖 Support This Project

If this toolkit has helped improve your security compliance, consider supporting its development:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support%20This%20Project-yellow.svg?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/mohammedsiddiqui)

Your support helps maintain and improve this toolkit with new CIS Benchmark updates, features, and compatibility with the latest Microsoft 365 controls!

### Option 2: Clone from GitHub

```powershell
# Clone the repository
git clone https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0.git
cd CIS-Microsoft-365-Foundations-Benchmark-v5.0.0

# Install required modules
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force
Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force
Install-Module -Name MSOnline -Scope CurrentUser -Force  # Legacy module (optional)
```

## 🔧 Prerequisites

### Required PowerShell Modules

All required modules are listed above in the installation section.

### Required Permissions

Your account needs the following permissions:

**Microsoft Graph API:**
- `Directory.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `UserAuthenticationMethod.Read.All`
- `IdentityRiskyUser.Read.All`
- `Application.Read.All`
- `Organization.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `RoleManagement.Read.All`
- `Reports.Read.All`

**Exchange Online:**
- View-Only Organization Management or higher

**SharePoint Online:**
- SharePoint Administrator or Global Administrator

**Microsoft Teams:**
- Teams Administrator or Global Administrator

## 🚀 Usage

### Quick Start (3 Steps)

```powershell
# Step 1: Import the module
Import-Module CIS-M365-Benchmark

# Step 2: Connect to Microsoft 365 (auto-detects tenant info)
Connect-CISBenchmark

# Step 3: Run the compliance check (no parameters needed!)
Invoke-CISBenchmark
```

### Module Commands

The module provides 5 main commands:

```powershell
# Display all available commands
Get-Command -Module CIS-M365-Benchmark

# 1. Connect to Microsoft 365 services
Connect-CISBenchmark

# 2. Run compliance checks (auto-detection mode)
Invoke-CISBenchmark

# 3. Display module information and version
Get-CISBenchmarkInfo

# 4. Check prerequisites and module versions
Test-CISBenchmarkPrerequisites

# 5. Get detailed help on any command
Get-Help Invoke-CISBenchmark -Full
Get-Help Connect-CISBenchmark -Full
```

### Basic Usage Examples

```powershell
# Simplest usage - auto-detect everything
Connect-CISBenchmark
Invoke-CISBenchmark

# Specify tenant domain and SharePoint URL manually
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

# Check only L1 (baseline) controls
Invoke-CISBenchmark -ProfileLevel "L1"

# Check only L2 (enhanced security) controls
Invoke-CISBenchmark -ProfileLevel "L2"

# Custom output directory
Invoke-CISBenchmark -OutputPath "C:\CIS-Reports"

# Verbose output for troubleshooting
Invoke-CISBenchmark -Verbose
```

### Advanced Usage Examples

```powershell
# Full example with all parameters
Connect-CISBenchmark
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com" `
    -ProfileLevel "All" `
    -OutputPath "C:\Security\CIS-Reports" `
    -Verbose

# One-liner for automation/scripts
Import-Module CIS-M365-Benchmark; Connect-CISBenchmark; Invoke-CISBenchmark

# Check specific control (for testing)
Get-CISBenchmarkControl -ControlNumber "5.2.2.1"
```

### Legacy Script Usage

You can also run the script directly without installing as a module:

```powershell
# Run the standalone script
.\CIS-M365-Compliance-Checker.ps1 `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com"
```

## 📊 Output Reports

The script generates two types of reports:

### 1. HTML Report
- **File**: `CIS-M365-Compliance-Report_YYYYMMDD_HHMMSS.html`
- Professional, color-coded HTML report
- Pass (Green), Fail (Red), Manual (Yellow), Error (Orange)
- Includes remediation steps for each failed control
- Summary dashboard with compliance statistics

### 2. CSV Report
- **File**: `CIS-M365-Compliance-Report_YYYYMMDD_HHMMSS.csv`
- Comma-separated values for easy import into Excel
- Includes all control details and results
- Perfect for tracking over time or further analysis

## 📈 Sample Output

```
================================================================
  CIS Microsoft 365 Foundations Benchmark v5.0.0
  Compliance Checker v2.4.0
================================================================

[2025-01-14 15:30:12] [Info] Checking required PowerShell modules...
[2025-01-14 15:30:12] [Success] All required modules are installed
[2025-01-14 15:30:12] [Info] Auto-detected tenant: contoso.onmicrosoft.com
[2025-01-14 15:30:12] [Info] SharePoint Admin URL: https://contoso-admin.sharepoint.com
[2025-01-14 15:30:12] [Info] Connecting to Microsoft 365 services...
[2025-01-14 15:30:45] [Success] Connected to Microsoft Graph
[2025-01-14 15:31:05] [Success] Connected to Exchange Online
[2025-01-14 15:31:10] [Success] Connected to SharePoint Online
[2025-01-14 15:31:30] [Success] Connected to Microsoft Teams
[2025-01-14 15:31:36] [Warning] MSOnline connection optional - continuing...

[2025-01-14 15:31:36] [Info] Starting CIS compliance checks...
[2025-01-14 15:31:38] [Info] Checking Section 1: Microsoft 365 Admin Center...
[2025-01-14 15:32:15] [Info] Checking Section 2: Microsoft 365 Defender...
[2025-01-14 15:33:42] [Info] Checking Section 5: Microsoft Entra Admin Center...

================================================================
  Compliance Check Complete
================================================================

Total Controls Checked: 130
Passed: 52
Failed: 28
Manual Review Required: 41
Errors: 9

Automated Compliance Rate: 68.42%
Overall Pass Rate: 65.00%

Reports saved to:
  HTML: .\CIS-M365-Compliance-Report_20250114_153545.html
  CSV:  .\CIS-M365-Compliance-Report_20250114_153545.csv

[2025-01-14 15:35:45] [Success] Assessment complete!
```

## 🛠️ Troubleshooting

### Common Issues

**Issue: Multiple sign-in prompts**
- **Solution**: This is normal. Each M365 service (Graph, Exchange, SharePoint, Teams) may prompt separately. Keep your browser window open after the first authentication to help reduce prompts.

**Issue: "Module not found" error**
- **Solution**: Install missing modules:
  ```powershell
  Install-Module -Name <ModuleName> -Scope CurrentUser -Force
  ```

**Issue: Permission denied errors**
- **Solution**: Ensure your account has Global Reader or equivalent permissions for all M365 services.

**Issue: Connection timeout**
- **Solution**: Check your network connection and firewall settings. Ensure you can reach `*.microsoft.com` and `*.microsoftonline.com`.

**Issue: DLP or MSOnline cmdlet errors**
- **Solution**: These are marked as "Manual" if the cmdlets aren't available. This is normal and doesn't affect other checks.

## 🔐 Security Considerations

- ✅ **Read-Only**: Script only reads configuration, never modifies settings
- ✅ **Secure Auth**: Uses OAuth 2.0 modern authentication
- ✅ **No Credentials Stored**: Authentication tokens are session-based only
- ✅ **Audit Trail**: All checks are logged with timestamps
- ⚠️ **Sensitive Data**: Reports may contain tenant configuration details - store securely

## 📜 License

This project is provided as-is under the MIT License for security assessment purposes. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Report Issues
Found a bug or have a feature request? [Open an issue](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)

### Submit Feedback
Have suggestions for improvements? [Share your feedback](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues/new)

### Support This Project
If this toolkit has helped improve your security compliance:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg?style=for-the-badge)](https://buymeacoffee.com/mohammedsiddiqui)

## 📚 References

- [CIS Microsoft 365 Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [Microsoft 365 Security Best Practices](https://docs.microsoft.com/en-us/microsoft-365/security/)

## 👨‍💻 Author

**Mohammed Siddiqui**
- 🐙 GitHub: [@mohammedsiddiqui6872](https://github.com/mohammedsiddiqui6872)
- 💼 LinkedIn: [Let's Chat!](https://www.linkedin.com/in/mohammedsiddiqui6872/)
- ☕ Support: [Buy Me a Coffee](https://buymeacoffee.com/mohammedsiddiqui)

## 🙏 Acknowledgments

- CIS (Center for Internet Security) for the comprehensive benchmark
- Microsoft for providing Graph API and PowerShell modules
- The Microsoft 365 security community

## 🔗 Links

- 📦 [PowerShell Gallery](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
- 🐙 [GitHub Repository](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0)
- 🐛 [Report Issues](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💬 [Submit Feedback](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues/new)
- 👔 [LinkedIn](https://www.linkedin.com/in/mohammedsiddiqui6872/)
- ☕ [Buy Me a Coffee](https://buymeacoffee.com/mohammedsiddiqui)

---

## 📞 Support

For issues, questions, or suggestions:
- 🐛 [Open an Issue](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💬 [Start a Discussion](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/discussions)

---

## ⚠️ Disclaimer

This toolkit is not affiliated with or endorsed by Microsoft Corporation or CIS (Center for Internet Security). Microsoft, Microsoft 365, Azure Active Directory, and related trademarks are property of Microsoft Corporation. CIS and CIS Benchmarks are trademarks of CIS.

This script is provided as-is for compliance assessment purposes. Always test in a non-production environment first. The authors are not responsible for any issues that may arise from using this script.

---

**⭐ If you find this tool helpful, please consider giving it a star!**

**Generated with** ❤️ **for better security compliance**

© 2025 Mohammed Siddiqui. All rights reserved.
