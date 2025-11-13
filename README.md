# CIS Microsoft 365 Foundations Benchmark v5.0.0 - Automated Compliance Checker

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/CIS-M365-Benchmark.svg)](https://www.powershellgallery.com/packages/CIS-M365-Benchmark)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v5.0.0-orange.svg)](https://www.cisecurity.org/)

A comprehensive PowerShell script that audits your Microsoft 365 environment against **all 130 CIS Microsoft 365 Foundations Benchmark v5.0.0 controls** and generates detailed HTML and CSV compliance reports.

## 🚀 Features

- ✅ **130 Automated Compliance Checks** across all M365 services
- 📊 **70-75% Fully Automated** - Most checks run automatically via Microsoft Graph API
- 📈 **Real-time Progress Tracking** - See exactly what's being checked
- 📄 **Dual Report Format** - Both HTML and CSV reports generated
- 🎯 **Profile-based Filtering** - Check L1, L2, or All controls
- 🔐 **Secure Authentication** - Uses modern OAuth 2.0 authentication
- 🛡️ **No Data Modification** - Read-only assessment, no changes to your environment
- 📝 **Actionable Remediation** - Each failed check includes remediation steps

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

### Quick Start (Recommended)

```powershell
# Step 1: Install the module
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser

# Step 2: Run compliance check (that's it!)
Invoke-CISBenchmark -TenantDomain "your-tenant.onmicrosoft.com" `
                    -SharePointAdminUrl "https://your-tenant-admin.sharepoint.com"

# All prerequisites install automatically on first run!
```

> **New in v2.2.1:** Prerequisites install automatically! No manual module installation needed.

### What Happens Behind the Scenes

When you run `Invoke-CISBenchmark` for the first time, the module automatically:
1. Detects missing prerequisite modules
2. Installs them silently with progress feedback:
   - Microsoft.Graph
   - ExchangeOnlineManagement
   - Microsoft.Online.SharePoint.PowerShell
   - MicrosoftTeams
   - MSOnline (optional legacy module)
3. Proceeds with compliance checks

### Manual Installation (Optional)

If you prefer to install prerequisites manually:

```powershell
# Install the module
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser

# Import and check prerequisites
Import-Module CIS-M365-Benchmark
Test-CISBenchmarkPrerequisites

# Install missing modules manually
Install-CISBenchmarkPrerequisites
```

### Alternative: Clone from GitHub

```powershell
# Clone the repository
git clone https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0.git
cd CIS-Microsoft-365-Foundations-Benchmark-v5.0.0

# Run the script directly (prerequisites install automatically)
.\CIS-M365-Compliance-Checker.ps1 -TenantDomain "your-tenant.onmicrosoft.com" `
                                   -SharePointAdminUrl "https://your-tenant-admin.sharepoint.com"
```

## 🔧 Prerequisites

### Required PowerShell Modules

The following modules are **automatically installed** when you first use the module:
- **Microsoft.Graph** - For Microsoft Graph API access
- **ExchangeOnlineManagement** - For Exchange Online checks
- **Microsoft.Online.SharePoint.PowerShell** - For SharePoint Online checks
- **MicrosoftTeams** - For Teams configuration checks
- **MSOnline** - Legacy module (optional, for backward compatibility)

No manual installation required!

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

### Module Commands

After installing the module, you can use the following commands:

```powershell
# Import the module
Import-Module CIS-M365-Benchmark

# See available commands
Get-Command -Module CIS-M365-Benchmark

# Display module information
Get-CISBenchmarkInfo

# Check which prerequisite modules are installed
Test-CISBenchmarkPrerequisites

# Install missing prerequisite modules (New in v2.2.0!)
Install-CISBenchmarkPrerequisites

# Install without prompts (for automation)
Install-CISBenchmarkPrerequisites -Force

# Get help on a specific command
Get-Help Invoke-CISBenchmark -Full
```

### Basic Usage

```powershell
# Run all compliance checks
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com"
```

### Advanced Usage

```powershell
# Check only L1 (baseline) controls
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com" `
    -ProfileLevel "L1"

# Check only L2 (enhanced security) controls
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com" `
    -ProfileLevel "L2"

# Custom output path
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com" `
    -OutputPath "C:\CIS-Reports"

# Run with verbose output
Invoke-CISBenchmark `
    -TenantDomain "contoso.onmicrosoft.com" `
    -SharePointAdminUrl "https://contoso-admin.sharepoint.com" `
    -Verbose
```

### Legacy Script Usage

You can also run the script directly without installing as a module:

```powershell
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
  Compliance Checker
================================================================

[2025-11-11 21:25:06] [Info] Checking required PowerShell modules...
[2025-11-11 21:25:06] [Success] All required modules are installed
[2025-11-11 21:25:06] [Info] Connecting to Microsoft 365 services...
[2025-11-11 21:25:35] [Success] Connected to Microsoft Graph
[2025-11-11 21:25:55] [Success] Connected to Exchange Online
[2025-11-11 21:26:00] [Success] Connected to SharePoint Online
[2025-11-11 21:26:20] [Success] Connected to Microsoft Teams
[2025-11-11 21:26:26] [Warning] MSOnline connection optional - continuing...

[2025-11-11 21:26:26] [Info] Starting CIS compliance checks...

================================================================
  Compliance Check Complete
================================================================

Total Controls Checked: 130
Passed: 45
Failed: 32
Manual Review Required: 41
Errors: 2

Automated Compliance Rate: 68.46%

Reports saved to:
  HTML: .\CIS-M365-Compliance-Report_20251111_212721.html
  CSV:  .\CIS-M365-Compliance-Report_20251111_212721.csv
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

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📚 References

- [CIS Microsoft 365 Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [Microsoft 365 Security Best Practices](https://docs.microsoft.com/en-us/microsoft-365/security/)

## 👥 Authors

- **Mohammed Siddiqui** - [GitHub](https://github.com/mohammedsiddiqui6872)

## 🙏 Acknowledgments

- CIS (Center for Internet Security) for the comprehensive benchmark
- Microsoft for providing Graph API and PowerShell modules
- The Microsoft 365 security community

## 📞 Support

For issues, questions, or suggestions:
- 🐛 [Open an Issue](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💬 [Start a Discussion](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/discussions)

---

**⭐ If you find this tool helpful, please consider giving it a star!**

**📢 Disclaimer**: This script is provided as-is for compliance assessment purposes. Always test in a non-production environment first. The authors are not responsible for any issues that may arise from using this script.
