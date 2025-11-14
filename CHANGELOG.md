# Changelog

All notable changes to the CIS Microsoft 365 Foundations Benchmark Compliance Checker.

## [2.3.9] - Current Version

### Critical False Positive Fixes - Batch 1

**Fixed FOUR Critical Controls**:

1. **Control 5.2.2.12 - Device Code Flow Blocking**: Fixed completely wrong property check. Now properly checks for Conditional Access policy with `AuthenticationFlows.TransferMethods` containing "deviceCodeFlow" and grant control set to "block". Previous implementation incorrectly checked `AllowedToUseSSPR` which is for admin password reset, not device code flow.

2. **Control 7.3.3 - Custom Script on Personal Sites**: Fixed tenant-only check. Now samples up to 100 actual OneDrive personal sites to verify `DenyAddAndCustomizePages` setting. Previous implementation only checked tenant default which doesn't affect existing sites.

3. **Control 2.4.4 - ZAP for Teams**: Fixed duplicate/wrong check. Now uses `Get-TeamsProtectionPolicy` and checks `ZapEnabled` property for Teams messages. Previous implementation incorrectly used `Get-AtpPolicyForO365.EnableATPForSPOTeamsODB` which is for Safe Attachments, not ZAP.

4. **Control 6.1.2 - Mailbox Audit Actions**: Fixed missing validation. Now actually validates audit actions (Owner, Delegate, Admin) match CIS requirements by sampling mailboxes. Previous implementation only checked if auditing was enabled org-wide without validating which actions were being audited.

## [2.3.8] - Previous Version

### Multiple Critical Fixes for False Positives

**Fixed THREE False Positive Controls**:

1. **Control 5.2.3.2 - Custom Banned Passwords**: Now correctly detects custom banned password lists using the proper directory settings API (`Get-MgBetaDirectorySetting` with template ID `5cf42378-d67d-4f36-ba46-e8b86229381d`). Previous implementation was checking incorrect property.

2. **Control 5.2.4.1 - SSPR Enabled for All**: Changed to manual control. Microsoft does NOT provide Graph API to check SSPR scope (All vs Selected vs None). The `authorizationPolicy.allowedToUseSSPR` only applies to administrators, not regular users.

3. **Control 7.2.3 - External Content Sharing**: Now correctly accepts "New and existing guests" (`ExternalUserSharingOnly`) as compliant per CIS Benchmark recommendations. This is the recommended secure configuration for external collaboration.

## [2.3.7] - Previous Version

### Bug Fix - Microsoft Authenticator Number Matching Detection

**Fixed Control 5.2.3.1**: Corrected hashtable property access for Microsoft Authenticator MFA fatigue protection settings. The control was returning empty values for number matching due to incorrect nested hashtable property access. Now properly detects both number matching and app context configuration.

## [2.3.4] - Previous Version

### Latest Updates

**Module Features:**
- ✅ **130 Automated Compliance Checks** across all M365 services
- 📊 **68% Automation Coverage** - Most checks run automatically
- 📈 **Zero-Parameter Usage** - Auto-detection of tenant information
- 🔐 **Secure Authentication** - Modern OAuth 2.0 with `Connect-CISBenchmark`
- 📄 **Dual Report Format** - HTML and CSV reports with actionable remediation
- 🎯 **Profile Filtering** - Check L1, L2, or All controls
- 🛡️ **Read-Only Assessment** - No modifications to your environment

**Installation:**
```powershell
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser
Connect-CISBenchmark
Invoke-CISBenchmark
```

### What's Covered

**Compliance Checks Across 9 Sections:**
1. Microsoft 365 Admin Center (8 controls)
2. Microsoft 365 Defender (14 controls)
3. Microsoft Purview (3 controls)
4. Microsoft Intune Admin Center (2 controls)
5. Microsoft Entra Admin Center (41 controls)
6. Exchange Admin Center (14 controls)
7. SharePoint Admin Center (14 controls)
8. Microsoft Teams Admin Center (13 controls)
9. Microsoft Fabric / Power BI (11 controls)

### Technical Highlights

- Auto-detection of tenant domain and SharePoint admin URL
- Automatic prerequisite module installation and updates
- Enhanced HTML reports with modern UI and floating action buttons
- Comprehensive error handling and graceful fallbacks
- PowerShell 5.1 and 7+ compatibility
- Microsoft.Graph 2.0+ support with automatic version management

---

## Support

- 🐛 [Report Issues](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💬 [Discussions](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/discussions)
- ☕ [Support Development](https://buymeacoffee.com/mohammedsiddiqui)
