# CIS Microsoft 365 Foundations Benchmark v6.0.0 - Automated Compliance Checker

[![PowerShell Gallery Version](https://img.shields.io/badge/Version-3.0.3-blue.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v6.0.0-orange.svg)](https://www.cisecurity.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg)](https://buymeacoffee.com/mohammedsiddiqui)

A comprehensive PowerShell module that audits your Microsoft 365 environment against **all 140 CIS Microsoft 365 Foundations Benchmark v6.0.0 controls** and generates detailed HTML and CSV compliance reports.

## What's New in v3.0.3

**v3.0.3 - Device Code Authentication Fix**
- **Device code auth now works for all services**: `-UseDeviceCode` now propagates to SharePoint Online (`-UseSystemBrowser $true`) and Teams (`-UseDeviceAuthentication`)
- **Device code now works on PowerShell 7+**: Previously ignored on PS 7+, now works on both PS 5.1 and 7+
- Thanks to Mateusz Jagiello for identifying and testing the fix

**v3.0.0 - CIS Benchmark v6.0.0 Upgrade**

- **12 New Controls Added** (140 total, up from 130):
  - 1.3.9 - Shared bookings page restrictions
  - 2.1.15 - Outbound anti-spam message limits
  - 5.1.3.2 - Security group creation restrictions
  - 5.1.4.1-6 - Device management controls (Entra join, LAPS, BitLocker)
  - 5.2.3.7 - Email OTP authentication method
  - 6.5.5 - Direct Send submission rejection
  - 9.1.12 - Service principal workspace/pipeline restrictions
- **2 Controls Removed** per CIS v6.0.0: 7.3.3 and 7.3.4 (custom script execution)
- **MSOL Dependency Removed**: MSOnline module retired by Microsoft; migrated to Graph API
- **Performance**: Cached redundant API calls (45 down to 7, 80% reduction)
- **PowerShellNerd Branding**: Logo in HTML report header and floating action button

**v2.6.0 Bug Fixes (included)**
- Fixed CIS 2.1.6: Correct cmdlet `Get-HostedOutboundSpamFilterPolicy`
- Fixed CIS 5.1.6.2: Accept both compliant guest access levels
- Fixed CIS 5.2.3.4: Added `-All` parameter for full user retrieval
- Fixed CIS 5.3.4/5.3.5: Replaced broken beta API with `Get-MgPolicyRoleManagementPolicyAssignment`
- Fixed SPO OAuth on PowerShell 7+ with `-UseWindowsPowerShell`

## Features

- **140 Compliance Controls** across all M365 services
- **66% Fully Automated** - 92 controls run automatically via Microsoft Graph API
- **Zero-Parameter Authentication** - `Connect-CISBenchmark` for easy setup
- **Dual Report Format** - Professional HTML and CSV reports with floating action buttons
- **Profile-based Filtering** - Check L1, L2, or All controls
- **Secure Authentication** - Modern OAuth 2.0 with persistent token caching
- **Read-Only Assessment** - No changes to your environment
- **Actionable Remediation** - Each failed check includes specific remediation steps
- **PowerShell 5.1 & 7+ Compatible** - Works on Windows PowerShell and PowerShell Core
- **Cached API Calls** - Minimized redundant Microsoft Graph and service calls

## What Gets Checked

The script performs comprehensive checks across **9 major sections**:

### Section 1: Microsoft 365 Admin Center (15 controls)
- Administrative account configurations
- Global admin count validation (2-4 admins)
- Public group management
- Shared mailbox security
- Password expiration policies
- Calendar sharing, idle session, user-owned apps settings
- **NEW**: Shared bookings page restrictions (1.3.9)

### Section 2: Microsoft 365 Defender (20 controls)
- Safe Links for Office applications
- Common attachment type filters
- Malware notification settings
- Safe Attachments policies
- SPF, DKIM, and DMARC records
- Anti-phishing policies
- Connection filter configurations
- Zero-hour auto purge settings
- Priority account protection
- **NEW**: Outbound anti-spam message limits (2.1.15)

### Section 3: Microsoft Purview (4 controls)
- Audit log search enabled
- DLP policies enabled (Exchange & Teams)
- Sensitivity label policies
- Communication compliance

### Section 4: Microsoft Intune Admin Center (2 controls)
- Device compliance policy settings
- Personal device enrollment restrictions

### Section 5: Microsoft Entra Admin Center (45 controls)

#### Identity & Access (5.1.x - 19 controls)
- Cloud-only administrative accounts
- Emergency access account configuration
- Third-party app registration restrictions
- Tenant creation restrictions
- Entra admin center access controls
- Dynamic groups for guest users
- User consent and guest access settings
- **NEW**: Security group creation restrictions (5.1.3.2)
- **NEW**: Device management - Entra join, device limits, admin roles, LAPS, BitLocker (5.1.4.1-6)

#### Conditional Access (5.2.2.x - 12 controls)
- MFA for administrative roles and all users
- Block legacy authentication
- Admin sign-in frequency
- User risk and sign-in risk policies
- Managed device requirements
- Intune enrollment sign-in frequency

#### Authentication Methods (5.2.3.x - 7 controls)
- Microsoft Authenticator MFA fatigue protection
- Custom banned password lists
- All users MFA capable
- Weak authentication methods disabled (SMS/Voice)
- System-preferred MFA enabled
- **NEW**: Email OTP authentication method disabled (5.2.3.7)

#### Password Reset (5.2.4.x - 1 control)
- Self-service password reset enabled

#### Identity Governance (5.3.x - 5 controls)
- Privileged Identity Management (PIM) configured
- Access reviews for guest users and privileged roles
- Global Administrator and Privileged Role Administrator approval

### Section 6: Exchange Admin Center (12 controls)
- Organization audit enabled
- Mailbox audit configurations and bypass checks
- Mail forwarding restrictions
- Transport rule whitelisting
- External email identification
- Outlook add-in restrictions
- Modern authentication enabled
- MailTips enabled
- OWA storage provider restrictions
- SMTP AUTH disabled
- **NEW**: Direct Send submission rejection (6.5.5)

### Section 7: SharePoint Admin Center (13 controls)
- Modern authentication requirements
- Azure AD B2B integration
- External content and OneDrive sharing restrictions
- Guest re-sharing prevention
- Domain allow/deny lists
- Link sharing configurations and guest link expiration
- Email verification requirements
- Default link permissions
- Infected file download blocking
- OneDrive sync restrictions

*Note: Controls 7.3.3 and 7.3.4 were removed in CIS Benchmark v6.0.0*

### Section 8: Microsoft Teams Admin Center (17 controls)
- External file sharing restrictions
- Channel email settings
- External domain restrictions
- Unmanaged Teams user blocking
- External conversation initiation
- Skype communication settings
- App permission policies
- Anonymous meeting join settings
- Lobby bypass configurations
- Meeting chat restrictions
- Presenter role limitations
- External control restrictions
- Meeting recording defaults

### Section 9: Microsoft Fabric / Power BI (12 controls)
- Guest user access restrictions
- External user invitations
- Content sharing restrictions
- Publish to web restrictions
- R and Python visual restrictions
- Sensitivity labels configuration
- Shareable link restrictions
- External data sharing
- ResourceKey authentication blocking
- Service principal API access
- Service principal profile creation
- **NEW**: Service principal workspace/pipeline restrictions (9.1.12)

## Automation Coverage

| Category | Total Controls | Automated | Manual | Coverage |
|----------|---------------|-----------|--------|----------|
| **Section 1: M365 Admin** | 15 | 5 | 10 | 33% |
| **Section 2: M365 Defender** | 20 | 15 | 5 | 75% |
| **Section 3: Purview** | 4 | 3 | 1 | 75% |
| **Section 4: Intune** | 2 | 2 | 0 | 100% |
| **Section 5: Entra ID** | 45 | 27 | 18 | 60% |
| **Section 6: Exchange** | 12 | 11 | 1 | 92% |
| **Section 7: SharePoint** | 13 | 12 | 1 | 92% |
| **Section 8: Teams** | 17 | 17 | 0 | 100% |
| **Section 9: Power BI** | 12 | 0 | 12 | 0% |
| **TOTAL** | **140** | **92** | **48** | **66%** |

## Installation

### Option 1: Install from PowerShell Gallery (Recommended)

```powershell
# Install the latest version from PowerShell Gallery
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
```

### Support This Project

If this toolkit has helped improve your security compliance, consider supporting its development:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support%20This%20Project-yellow.svg?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/mohammedsiddiqui)

### Option 2: Clone from GitHub

```powershell
# Clone the repository
git clone https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark.git
cd CIS-Microsoft-365-Foundations-Benchmark

# Install required modules
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force
Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force
```

## Prerequisites

### Required PowerShell Modules

| Module | Purpose |
|--------|---------|
| `Microsoft.Graph` (v2.0+) | Entra ID, Conditional Access, PIM, Authentication Methods |
| `ExchangeOnlineManagement` | Exchange Online configuration checks |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online tenant settings |
| `MicrosoftTeams` | Teams meeting, messaging, and federation policies |

### Key Cmdlets Used

| Cmdlet | Controls |
|--------|----------|
| `Get-MgIdentityConditionalAccessPolicy` | 5.2.2.x (Conditional Access) |
| `Get-MgPolicyRoleManagementPolicyAssignment` | 5.3.4, 5.3.5 (PIM approval) |
| `Get-MgReportAuthenticationMethodUserRegistrationDetail` | 5.2.3.4 (MFA registration) |
| `Get-HostedOutboundSpamFilterPolicy` | 2.1.6 (Outbound spam notifications) |
| `Get-SPOTenant` | 7.x (SharePoint settings) |
| `Get-CsTeamsMeetingPolicy` | 8.x (Teams meeting policies) |
| `Get-OrganizationConfig` | 6.x (Exchange org settings) |
| `Get-MalwareFilterPolicy` | 2.1.x (Defender malware filters) |

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

## Usage

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

# Use device code authentication (for headless/remote sessions)
Connect-CISBenchmark -UseDeviceCode
Invoke-CISBenchmark

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

## Output Reports

The script generates two types of reports:

### 1. HTML Report
- **File**: `CIS-M365-Compliance-Report_YYYYMMDD_HHMMSS.html`
- Professional dark-themed HTML report with PowerShellNerd branding
- Pass (Green), Fail (Red), Manual (Yellow), Error (Orange)
- Includes remediation steps for each failed control
- Summary dashboard with compliance statistics and progress bars
- L1/L2 profile breakdown
- Filterable results table with search
- Floating action buttons (PowerShellNerd, GitHub, Issues, Feedback, LinkedIn, Buy Me a Coffee)

### 2. CSV Report
- **File**: `CIS-M365-Compliance-Report_YYYYMMDD_HHMMSS.csv`
- Comma-separated values for easy import into Excel
- Includes all control details and results
- Perfect for tracking over time or further analysis

## Sample Output

```
================================================================
  CIS Microsoft 365 Foundations Benchmark v6.0.0
  Compliance Checker v3.0.3
================================================================

[2026-02-21 15:30:12] [Info] Checking required PowerShell modules...
[2026-02-21 15:30:12] [Success] All required modules are installed
[2026-02-21 15:30:12] [Info] Auto-detected tenant: contoso.onmicrosoft.com
[2026-02-21 15:30:12] [Info] SharePoint Admin URL: https://contoso-admin.sharepoint.com
[2026-02-21 15:30:12] [Info] Connecting to Microsoft 365 services...
[2026-02-21 15:30:45] [Success] Connected to Microsoft Graph
[2026-02-21 15:31:05] [Success] Connected to Exchange Online
[2026-02-21 15:31:10] [Success] Connected to SharePoint Online
[2026-02-21 15:31:30] [Success] Connected to Microsoft Teams

[2026-02-21 15:31:36] [Info] Starting CIS compliance checks...
[2026-02-21 15:31:38] [Info] Checking Section 1: Microsoft 365 Admin Center...
[2026-02-21 15:32:15] [Info] Checking Section 2: Microsoft 365 Defender...
[2026-02-21 15:33:42] [Info] Checking Section 5: Microsoft Entra Admin Center...

================================================================
  Compliance Check Complete
================================================================

Total Controls Checked: 140
Passed: 58
Failed: 30
Manual Review Required: 48
Errors: 4

Automated Compliance Rate: 66%
Overall Pass Rate: 65.91%

Reports saved to:
  HTML: .\CIS-M365-Compliance-Report_20260221_153545.html
  CSV:  .\CIS-M365-Compliance-Report_20260221_153545.csv

[2026-02-21 15:35:45] [Success] Assessment complete!
```

## Troubleshooting

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

**Issue: SPO authentication fails on PowerShell 7+**
- **Solution**: The module automatically handles this by importing `Microsoft.Online.SharePoint.PowerShell` with `-UseWindowsPowerShell` on PS 7+. If issues persist, try running from Windows PowerShell 5.1.

**Issue: PIM or Identity Governance errors**
- **Solution**: Ensure PIM is licensed and configured in your tenant. Controls 5.3.4 and 5.3.5 use `Get-MgPolicyRoleManagementPolicyAssignment` which requires Entra ID P2.

## Security Considerations

- **Read-Only**: Script only reads configuration, never modifies settings
- **Secure Auth**: Uses OAuth 2.0 modern authentication
- **No Credentials Stored**: Authentication tokens are session-based only
- **No MSOL Dependency**: Fully migrated to Microsoft Graph API (MSOnline module retired March 2025)
- **Audit Trail**: All checks are logged with timestamps
- **Sensitive Data**: Reports may contain tenant configuration details - store securely

## License

This project is provided as-is under the MIT License for security assessment purposes. See the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Here's how you can help:

### Report Issues
Found a bug or have a feature request? [Open an issue](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues)

### Submit Feedback
Have suggestions for improvements? [Share your feedback](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues/new)

### Support This Project
If this toolkit has helped improve your security compliance:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg?style=for-the-badge)](https://buymeacoffee.com/mohammedsiddiqui)

## References

- [CIS Microsoft 365 Foundations Benchmark v6.0.0](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [Microsoft 365 Security Best Practices](https://docs.microsoft.com/en-us/microsoft-365/security/)

## Author

**Mohammed Siddiqui**
- GitHub: [@mohammedsiddiqui6872](https://github.com/mohammedsiddiqui6872)
- LinkedIn: [Let's Chat!](https://www.linkedin.com/in/mohammedsiddiqui6872/)
- Website: [PowerShellNerd](https://powershellnerd.com)
- Support: [Buy Me a Coffee](https://buymeacoffee.com/mohammedsiddiqui)

## Acknowledgments

- CIS (Center for Internet Security) for the comprehensive benchmark
- Microsoft for providing Graph API and PowerShell modules
- The Microsoft 365 security community
- Thanks to ITEngineer-0815, M0nk3yOo, ozsaid, and Mateusz Jagiello for their contributions and issue reports

## Links

- [PowerShell Gallery](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
- [GitHub Repository](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark)
- [Report Issues](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues)
- [Submit Feedback](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues/new)
- [PowerShellNerd](https://powershellnerd.com)
- [LinkedIn](https://www.linkedin.com/in/mohammedsiddiqui6872/)
- [Buy Me a Coffee](https://buymeacoffee.com/mohammedsiddiqui)

---

## Disclaimer

This toolkit is not affiliated with or endorsed by Microsoft Corporation or CIS (Center for Internet Security). Microsoft, Microsoft 365, Azure Active Directory, and related trademarks are property of Microsoft Corporation. CIS and CIS Benchmarks are trademarks of CIS.

This script is provided as-is for compliance assessment purposes. Always test in a non-production environment first. The authors are not responsible for any issues that may arise from using this script.

---

**If you find this tool helpful, please consider giving it a star!**

**Generated with love for better security compliance**

(c) 2025 Mohammed Siddiqui. All rights reserved.
