# CIS Microsoft 365 Foundations Benchmark v6.0.0 - Automated Compliance Checker

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v6.0.0-orange.svg)](https://www.cisecurity.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg)](https://buymeacoffee.com/mohammedsiddiqui)

A comprehensive PowerShell module that audits your Microsoft 365 environment against **all 140 CIS Microsoft 365 Foundations Benchmark v6.0.0 controls** and generates detailed HTML and CSV compliance reports.

## What's New in v3.0.2

**v3.0.2 - Device Code Authentication Fix**
- **Device code auth now works for all services**: `-UseDeviceCode` now propagates to SharePoint Online (`-ModernAuth -UseSystemBrowser`) and Teams (`-UseDeviceAuthentication`)
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
- **Bug Fixes**: Fixed controls 2.1.6, 5.1.6.2, 5.2.3.4, 5.3.4, 5.3.5; SPO OAuth on PS 7+

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
- Administrative account configurations and global admin count validation
- Public group management and shared mailbox security
- Password expiration policies
- Calendar sharing, idle session, user-owned apps settings
- **NEW**: Shared bookings page restrictions (1.3.9)

### Section 2: Microsoft 365 Defender (20 controls)
- Safe Links, Safe Attachments, and anti-phishing policies
- Common attachment type filters and malware notifications
- SPF, DKIM, and DMARC records
- Connection filters and zero-hour auto purge
- Priority account protection
- **NEW**: Outbound anti-spam message limits (2.1.15)

### Section 3: Microsoft Purview (4 controls)
- Audit log search, DLP policies, sensitivity labels, communication compliance

### Section 4: Microsoft Intune Admin Center (2 controls)
- Device compliance policies and personal device enrollment restrictions

### Section 5: Microsoft Entra Admin Center (45 controls)

#### Identity & Access (5.1.x - 19 controls)
- Cloud-only administrative accounts, emergency access, global admin count
- App registration, tenant creation, admin center access restrictions
- Guest user access, user consent, dynamic groups
- **NEW**: Security group creation restrictions (5.1.3.2)
- **NEW**: Device management - Entra join, device limits, admin roles, LAPS, BitLocker (5.1.4.1-6)

#### Conditional Access (5.2.2.x - 12 controls)
- MFA for admins and all users, legacy authentication blocking
- Sign-in frequency, user/sign-in risk policies, managed devices

#### Authentication Methods (5.2.3.x - 7 controls)
- Authenticator MFA fatigue protection, banned passwords, MFA capable
- Weak methods disabled, system-preferred MFA
- **NEW**: Email OTP authentication method disabled (5.2.3.7)

#### Password Reset & Identity Governance (6 controls)
- Self-service password reset, PIM, access reviews, admin approval

### Section 6: Exchange Admin Center (12 controls)
- Organization and mailbox auditing, mail forwarding restrictions
- Transport rules, external email tagging, add-in restrictions
- Modern authentication, MailTips, OWA storage, SMTP AUTH
- **NEW**: Direct Send submission rejection (6.5.5)

### Section 7: SharePoint Admin Center (13 controls)
- Modern authentication, B2B integration, sharing restrictions
- Guest controls, link sharing, sync restrictions
- *Note: Controls 7.3.3 and 7.3.4 removed in CIS v6.0.0*

### Section 8: Microsoft Teams Admin Center (17 controls)
- External sharing, domain restrictions, app permissions
- Meeting policies, lobby, chat, presenter, recording settings

### Section 9: Microsoft Fabric / Power BI (12 controls)
- Guest access, external sharing, publish restrictions
- Sensitivity labels, service principal controls
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

### Quick Start (Recommended)

```powershell
# Step 1: Install the module
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser

# Step 2: Authenticate to Microsoft 365
Connect-CISBenchmark

# Step 3: Run compliance check (auto-detects tenant info!)
Invoke-CISBenchmark

# That's it! All prerequisites install automatically on first run.
```

### What Happens Behind the Scenes

When you run the commands for the first time, the module automatically:

1. **On `Connect-CISBenchmark`:**
   - Opens browser window for Microsoft 365 sign-in
   - Authenticates to Microsoft Graph with required permissions
   - Establishes secure session for compliance checks

2. **On `Invoke-CISBenchmark`:**
   - Auto-detects your tenant domain and SharePoint admin URL
   - Detects missing prerequisite modules
   - Installs them silently with progress feedback:
     - Microsoft.Graph (v2.0+)
     - ExchangeOnlineManagement
     - Microsoft.Online.SharePoint.PowerShell
     - MicrosoftTeams
   - Proceeds with compliance checks

### Alternative Authentication Methods

```powershell
# Use device code authentication (for remote sessions or MFA issues)
Connect-CISBenchmark -UseDeviceCode

# Then run the assessment
Invoke-CISBenchmark
```

### Manual Parameters (Optional)

If auto-detection doesn't work, you can still specify parameters manually:

```powershell
# Authenticate first
Connect-CISBenchmark

# Run with manual parameters
Invoke-CISBenchmark -TenantDomain "your-tenant.onmicrosoft.com" `
                    -SharePointAdminUrl "https://your-tenant-admin.sharepoint.com"
```

### Alternative: Clone from GitHub

```powershell
# Clone the repository
git clone https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark.git
cd CIS-Microsoft-365-Foundations-Benchmark

# Import the module
Import-Module .\CIS-M365-Benchmark\CIS-M365-Benchmark.psd1

# Authenticate and run
Connect-CISBenchmark
Invoke-CISBenchmark
```

## Prerequisites

### Required PowerShell Modules

The following modules are **automatically installed** when you first use the module:

| Module | Purpose |
|--------|---------|
| `Microsoft.Graph` (v2.0+) | Entra ID, Conditional Access, PIM, Authentication Methods |
| `ExchangeOnlineManagement` | Exchange Online configuration checks |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online tenant settings |
| `MicrosoftTeams` | Teams meeting, messaging, and federation policies |

No manual installation required!

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

### Module Commands

After installing the module, you can use the following commands:

```powershell
# Import the module (optional - auto-imports when you run commands)
Import-Module CIS-M365-Benchmark

# See available commands
Get-Command -Module CIS-M365-Benchmark

# Display module information
Get-CISBenchmarkInfo

# Check which prerequisite modules are installed
Test-CISBenchmarkPrerequisites

# Get help on authentication
Get-Help Connect-CISBenchmark -Full

# Get help on running assessments
Get-Help Invoke-CISBenchmark -Full
```

### Basic Usage

```powershell
# Step 1: Authenticate to Microsoft 365
Connect-CISBenchmark

# Step 2: Run all compliance checks (auto-detects tenant info)
Invoke-CISBenchmark
```

### Advanced Usage

```powershell
# Authenticate first
Connect-CISBenchmark

# Check only L1 (baseline) controls
Invoke-CISBenchmark -ProfileLevel "L1"

# Check only L2 (enhanced security) controls
Invoke-CISBenchmark -ProfileLevel "L2"

# Custom output path
Invoke-CISBenchmark -OutputPath "C:\CIS-Reports"

# Run with verbose output
Invoke-CISBenchmark -Verbose

# Combine multiple options
Invoke-CISBenchmark -ProfileLevel "L1" -OutputPath "C:\CIS-Reports" -Verbose
```

### Legacy Script Usage

You can also run the script directly without installing as a module:

```powershell
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
  Compliance Checker v3.0.2
================================================================

[2026-02-21 15:30:08] [Info] Checking required PowerShell modules...
[2026-02-21 15:30:08] [Success] All required modules are installed
[2026-02-21 15:30:08] [Info] Connecting to Microsoft 365 services...
[2026-02-21 15:30:12] [Info] Auto-detected tenant: contoso.onmicrosoft.com
[2026-02-21 15:30:12] [Info] Auto-detected SharePoint Admin URL: https://contoso-admin.sharepoint.com
[2026-02-21 15:30:35] [Success] Connected to Microsoft Graph
[2026-02-21 15:30:55] [Success] Connected to Exchange Online
[2026-02-21 15:31:00] [Success] Connected to SharePoint Online
[2026-02-21 15:31:20] [Success] Connected to Microsoft Teams

[2026-02-21 15:31:26] [Info] Starting CIS compliance checks...

================================================================
  Compliance Check Complete
================================================================

Total Controls Checked: 140
Passed: 58
Failed: 30
Manual Review Required: 48
Errors: 4

Automated Compliance Rate: 66%

Reports saved to:
  HTML: .\CIS-M365-Compliance-Report_20260221_153245.html
  CSV:  .\CIS-M365-Compliance-Report_20260221_153245.csv
```

## Troubleshooting

### Common Issues

**Issue: "Connect-CISBenchmark is not recognized"**
- **Solution**: Make sure you've installed the latest version:
  ```powershell
  Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser -Force
  Import-Module CIS-M365-Benchmark -Force
  ```

**Issue: Authentication browser window doesn't open**
- **Solution**: Use device code authentication instead:
  ```powershell
  Connect-CISBenchmark -UseDeviceCode
  ```

**Issue: "Tenant domain is empty" error**
- **Solution**: Ensure you've authenticated first with `Connect-CISBenchmark`, or specify parameters manually.

**Issue: Multiple sign-in prompts**
- **Solution**: This is normal. Each M365 service (Graph, Exchange, SharePoint, Teams) may prompt separately.

**Issue: SPO authentication fails on PowerShell 7+**
- **Solution**: The module automatically handles this by importing with `-UseWindowsPowerShell`. If issues persist, try running from Windows PowerShell 5.1.

**Issue: PIM or Identity Governance errors**
- **Solution**: Ensure PIM is licensed and configured. Controls 5.3.4/5.3.5 use `Get-MgPolicyRoleManagementPolicyAssignment` which requires Entra ID P2.

**Issue: Permission denied errors**
- **Solution**: Ensure your account has Global Reader or equivalent permissions for all M365 services.

## Security Considerations

- **Read-Only**: Script only reads configuration, never modifies settings
- **Secure Auth**: Uses OAuth 2.0 modern authentication
- **No Credentials Stored**: Authentication tokens are session-based only
- **No MSOL Dependency**: Fully migrated to Microsoft Graph API
- **Audit Trail**: All checks are logged with timestamps
- **Sensitive Data**: Reports may contain tenant configuration details - store securely

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

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

## Support

For issues, questions, or suggestions:
- [Open an Issue](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues)
- [Start a Discussion](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/discussions)
- [PowerShellNerd](https://powershellnerd.com)

## Support This Project

If you find this tool helpful and want to support continued development:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/mohammedsiddiqui)

Your support helps maintain and improve this project!

---

**If you find this tool helpful, please consider giving it a star!**

**Disclaimer**: This toolkit is not affiliated with or endorsed by Microsoft Corporation or CIS (Center for Internet Security). This script is provided as-is for compliance assessment purposes. Always test in a non-production environment first.
