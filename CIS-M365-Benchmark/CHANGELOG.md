# Changelog

All notable changes to the CIS Microsoft 365 Foundations Benchmark Compliance Checker will be documented in this file.

## [3.0.5] - 2026-02-24

### Fix
- **Fixed false positive DMARC check on `*.onmicrosoft.com` domains (Issue #9)**: Control 2.1.10 now skips `*.onmicrosoft.com` and `*.mail.onmicrosoft.com` domains since DMARC for these is managed by Microsoft and cannot be configured by tenants
- **Fixed false positive SPF check on `*.onmicrosoft.com` domains**: Control 2.1.8 now also skips Microsoft-managed onmicrosoft.com domains
- **Fixed false positive DKIM check on `*.onmicrosoft.com` domains**: Control 2.1.9 now excludes Microsoft-managed onmicrosoft.com domains from the disabled DKIM check

### Thanks
- Thanks to [heysurfer](https://github.com/heysurfer) for reporting the issue (#9)

## [3.0.4] - 2026-02-24

### Fix
- **Fixed malformed `-ErrorAction` parameters from v3.0.1**: Three `-ErrorAction Stop` additions landed on the wrong line (lines 251, 310, 1159), causing PowerShell to treat `-ErrorAction` as a standalone command instead of a parameter. Fixed by moving them back onto the same line as their cmdlet.
- **Fixed typo `Stopd` in control 1.2.2**: `Get-MgUser` call had `-ErrorAction Stopd` (typo) plus a duplicate `-ErrorAction SilentlyContinue` on the same line
- **Fixed property typo `AccountEnable`**: Changed to correct property name `AccountEnabled` in control 1.2.2

## [3.0.3] - 2026-02-23

### Fix
- **Device code authentication now works for all services**: When using `Connect-CISBenchmark -UseDeviceCode`, the device-friendly authentication is now propagated to SharePoint Online (`-UseSystemBrowser $true`) and Microsoft Teams (`-UseDeviceAuthentication`) instead of falling back to interactive browser/Authenticator prompts
- **Device code now works on PowerShell 7+**: Previously `-UseDeviceCode` was silently ignored on PS 7+; now it correctly uses device code authentication on both PS 5.1 and PS 7+
- **Fixed SPO parameter syntax**: Removed unnecessary `-ModernAuth` parameter; `-UseSystemBrowser $true` is sufficient for SharePoint Online

### Thanks
- Thanks to Mateusz Jagiello for identifying the fix and testing device code authentication across all services

## [3.0.1] - 2026-02-21

### Fix
- **Suppressed red error output in terminal**: Added `-ErrorAction Stop` to 30 API cmdlets inside try/catch blocks so errors are handled silently by catch blocks instead of printing red text to the terminal (e.g., PIM checks on tenants without Entra ID P2)

## [3.0.0] - 2026-02-21

### Major Update: CIS Benchmark v6.0.0
- **Upgraded from CIS Microsoft 365 Foundations Benchmark v5.0.0 to v6.0.0** (Issue #5)
- Total controls updated from 130 to 140

### New Controls (12 added in v6.0.0)
- **1.3.9** (L1): Ensure shared bookings pages are restricted to select users
- **2.1.15** (L1): Ensure outbound anti-spam message limits are in place
- **5.1.3.2** (L1): Ensure users cannot create security groups
- **5.1.4.1** (L2): Ensure the ability to join devices to Entra is restricted
- **5.1.4.2** (L1): Ensure the maximum number of devices per user is limited
- **5.1.4.3** (L1): Ensure the GA role is not added as a local administrator during Entra join
- **5.1.4.4** (L1): Ensure local administrator assignment is limited during Entra join
- **5.1.4.5** (L1): Ensure Local Administrator Password Solution is enabled
- **5.1.4.6** (L2): Ensure users are restricted from recovering BitLocker keys
- **5.2.3.7** (L2): Ensure the email OTP authentication method is disabled
- **6.5.5** (L2): Ensure Direct Send submissions are rejected
- **9.1.12** (L1): Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted

### Removed Controls (2 removed in v6.0.0)
- **7.3.3**: Ensure custom script execution is restricted on personal sites (removed by CIS)
- **7.3.4**: Ensure custom script execution is restricted on site collections (removed by CIS)

### Branding
- Added PowerShellNerd logo to HTML report header
- Added PowerShellNerd floating action button linking to [powershellnerd.com](https://powershellnerd.com)

### Thanks
- Thanks to M0nk3yOo for requesting the v6.0.0 upgrade (Issue #5)

## [2.6.0] - 2026-02-21

### Performance
- **Cached redundant API calls**: Reduced 45 API calls to 7 across all section functions (80% reduction)
  - `Get-MgIdentityConditionalAccessPolicy` cached in `Test-EntraID` (was called 10 times)
  - `Get-SPOTenant` cached in `Test-SharePointOnline` (was called 13 times)
  - `Get-CsTeamsMeetingPolicy` cached in `Test-MicrosoftTeams` (was called 9 times)
  - `Get-CsTenantFederationConfiguration` cached in `Test-MicrosoftTeams` (was called 4 times)
  - `Get-OrganizationConfig` cached in `Test-ExchangeOnline` (was called 4 times)
  - `Get-MalwareFilterPolicy` cached in `Test-M365Defender` (was called 3 times)
  - `Get-HostedContentFilterPolicy` cached in `Test-M365Defender` (was called 2 times)

### Bug Fixes
- **Fixed CIS 2.1.6**: Changed from `Get-HostedContentFilterPolicy` to correct cmdlet `Get-HostedOutboundSpamFilterPolicy` with proper properties (`NotifyOutboundSpamRecipients`, `NotifyOutboundSpam`)
- **Fixed CIS 5.1.6.2**: Now accepts both compliant guest access levels - "limited access" (`10dae51f-b6af-4016-8d66-8c2a99b929b3`) and "most restrictive" (`2af84b1e-32c8-42b7-82bc-daa82404023b`) per CIS benchmark
- **Fixed CIS 5.2.3.4**: Added missing `-All` parameter to `Get-MgReportAuthenticationMethodUserRegistrationDetail` to retrieve all users instead of only the first page
- **Fixed CIS 5.3.4**: Replaced broken beta API (`roleManagementPolicies`) with `Get-MgPolicyRoleManagementPolicyAssignment` for Global Administrator PIM approval check
- **Fixed CIS 5.3.5**: Same fix as 5.3.4 for Privileged Role Administrator PIM approval check
- **Fixed SPO OAuth on PowerShell 7+** (Issue #4): Added `-UseWindowsPowerShell` when importing `Microsoft.Online.SharePoint.PowerShell` on PS 7+ to resolve authentication failures

### New Cmdlet Support
- **`Get-HostedOutboundSpamFilterPolicy`**: Now used for CIS 2.1.6 (replaces incorrect `Get-HostedContentFilterPolicy`)
- **`Get-MgPolicyRoleManagementPolicyAssignment`**: Now used for CIS 5.3.4 and 5.3.5 PIM approval checks (replaces broken beta `roleManagementPolicies` API)
- **Microsoft Graph beta `perUserMfaState` filter**: Now used for CIS 5.1.2.1 per-user MFA check (replaces deprecated `Get-MsolUser`)

### Breaking Changes
- **Removed MSOnline (MSOL) dependency** (Issue #8): MSOnline module was retired by Microsoft in March 2025
  - Control 5.1.2.1 (Per-user MFA) now uses Microsoft Graph beta API instead of `Get-MsolUser`
  - Falls back to "Manual" if Graph beta endpoint is unavailable
  - MSOL is no longer installed, imported, or connected
  - One fewer authentication prompt during service connection

### Thanks
- Thanks to ITEngineer-0815 for reporting fixes for controls 2.1.6, 5.1.6.2, 5.2.3.4, 5.3.4, and 5.3.5
- Thanks to M0nk3yOo for reporting the SPO OAuth issue (#4)
- Thanks to ozsaid for reporting the MSOL issue (#8)

## [2.5.7] - 2025-12-09

### 🔧 Maintenance
- **Fixed Version Number Discrepancy**: Updated script header version to match module version
  - Script header was showing version 1.0 (outdated)
  - Updated to version 2.5.7 to match module manifest
  - Updated author information in script header
  - Updated date to reflect current version

## [2.5.6] - 2025-12-09

### 🐛 Bug Fixes
- **Fixed Device Code Authentication Issue**: Resolved authentication failure when using `-UseDeviceCode` parameter
  - Issue: After running `Connect-CISBenchmark -UseDeviceCode`, running `Invoke-CISBenchmark` would fail because the compliance checker script was attempting to re-authenticate without checking for existing Graph connection
  - Root cause: `Connect-M365Services` function in CIS-M365-Compliance-Checker.ps1 was blindly calling `Connect-MgGraph` without checking if already authenticated
  - Fix: Added check for existing Microsoft Graph context before attempting new connection
  - Now properly reuses the existing authenticated session established by `Connect-CISBenchmark`
  - Eliminates redundant authentication prompts and respects the original authentication method (device code, interactive, etc.)
  - Reported by community user Mateusz Jagiełło - thank you!

### Technical Details
- Modified `Connect-M365Services` function to call `Get-MgContext` first
- Only attempts new Graph connection if no valid context exists
- Displays "Microsoft Graph already connected - reusing existing session" message when reusing connection
- Maintains backward compatibility - still works if user hasn't pre-authenticated

## [2.5.5] - 2025-11-18

### 🐛 Bug Fixes
- **Fixed CIS 5.2.3.1 Test**: Handle missing numberMatchingRequiredState property in Microsoft Authenticator settings
  - Microsoft changed API behavior in 2025 where enabled number matching no longer returns the numberMatchingRequiredState property
  - Test was incorrectly failing when property was absent, treating it as "not configured"
  - Updated logic to treat absent numberMatchingRequiredState property as "default (enabled)"
  - This aligns with Microsoft's 2025 update making number matching enabled by default
  - Fixes false negatives for organizations with properly configured Microsoft Authenticator settings

## [2.5.4] - 2025-11-17

### 🐛 Critical Bug Fix
- **Fixed JavaScript Syntax Error in HTML Reports**: Resolved template literal issue
  - Fixed JavaScript template literals that were being incorrectly processed by PowerShell
  - Changed from ES6 template literals to string concatenation to avoid PowerShell variable expansion
  - Resolves "Uncaught SyntaxError: Unexpected number" error that broke all interactive features
  - All click handlers and search functionality now work correctly

## [2.5.3] - 2025-11-17

### 🐛 Bug Fixes
- **Improved Click Functionality in HTML Reports**: Simplified event handling for better reliability
  - Restored inline onclick handlers with global function scope
  - Removed complex event listener attachment that was causing timing issues
  - Ensures all interactive elements work consistently across browsers
  - Fixed tenant info dropdown, score card filtering, and search functionality

### ⚠️ Known Issues
- **PowerShell 7 Authentication**: Microsoft.Graph module has compatibility issues with PowerShell 7
  - Error: "Microsoft.Identity.Client.BaseAbstractApplicationBuilder" method not found
  - This is a known issue with the Microsoft.Graph authentication library
  - **Workaround**: Use PowerShell 5.1 which works perfectly
  - Module now provides clear guidance when PowerShell 7 authentication fails

### 📝 Documentation
- Added PowerShell 7 compatibility notes and workarounds
- Improved error messages for authentication issues
- Clear instructions for using PowerShell 5.1 as the recommended runtime

## [2.5.2] - 2025-11-17

### 🐛 Bug Fixes
- **Fixed Click Functionality**: Resolved critical issues with interactive elements in HTML reports
  - Converted all inline onclick handlers to programmatic event listeners
  - Fixed tenant name dropdown not responding to clicks
  - Fixed score card filtering not working when clicked
  - Added proper DOM ready detection with multiple fallback mechanisms
  - Enhanced event attachment reliability with defensive coding
  - Improved search box functionality with both keyup and input events
  - Added console logging for debugging event attachment
  - Ensures all interactive elements work across different browsers and security contexts

## [2.4.4] - 2025-01-17

### ✨ New Features
- **Real-time Search Box**: Added instant search functionality to HTML reports
  - Search across control number, title, level (L1/L2), status, and details
  - Live filtering as you type with result counter
  - Clear search to restore all results
  - Clears filter buttons when searching and vice versa

- **L1/L2 Level Tracking**: Added dedicated score cards for profile levels
  - New L1 Checks card showing passed/total L1 controls with compliance rate
  - New L2 Checks card showing passed/total L2 controls with compliance rate
  - Clickable cards to filter results by profile level
  - Console output includes L1/L2 statistics breakdown

- **Enhanced UI Design**: Modern, professional report styling
  - Compact summary boxes with reduced height for better space efficiency
  - Unified black background for all score cards
  - Animated white glowing borders with continuous pulsing effect
  - Color-coded text for easy status identification
  - Improved hover effects with enhanced glow
  - Active state shows blue glow when filtering

### Technical Details
- Added 8 new global counters: L1Total, L1Passed, L1Failed, L1Manual, L2Total, L2Passed, L2Failed, L2Manual
- Updated Add-Result function to track L1/L2 statistics separately
- Implemented searchTable() JavaScript function for real-time filtering
- Added data-level attribute to table rows for level-based filtering
- CSS animations using @keyframes for smooth border glow effect
- Enhanced filterResults() function to support both status and level filtering

### User Experience Improvements
- Search box positioned prominently above Detailed Results table
- Results counter displays "Found X results out of Y controls"
- Search supports partial matching across all columns
- Smooth transitions and professional animations throughout
- Better visual hierarchy with compact, consistent design

## [2.4.3] - 2025-01-17

### 🐛 Bug Fixes
- **Fixed Control 5.2.3.1**: False positive eliminated for Microsoft Authenticator MFA fatigue protection
  - Now accepts "default" state as compliant (Microsoft enabled number matching by default in 2025)
  - Added missing third check: `displayLocationInformationRequiredState` (geographic location)
  - CIS 5.2.3.1 requires THREE settings: (1) number matching, (2) app name display, (3) location display
  - Before: Only accepted "enabled" state and checked 2 of 3 required settings
  - After: Accepts both "enabled" and "default" states and checks all 3 required settings

### Technical Details
- Updated validation logic to accept `$state -eq "enabled" -or $state -eq "default"`
- Added `displayLocationInformationRequiredState` check per CIS Benchmark v5.0.0 requirement
- Enhanced details output to show all three setting states for better troubleshooting
- Updated remediation guidance to include all three required configuration steps

### Issue Reported
User reported false positive where number matching showed "not configured" despite being enabled by Microsoft's default settings.

## [2.1.1] - 2025-01-13

### 🐛 Bug Fixes
- **Fixed SharePointAdminUrl validation**: Parameter now accepts URLs with trailing slashes
  - Before: `https://tenant-admin.sharepoint.com/` would fail validation
  - After: Both `https://tenant-admin.sharepoint.com` and `https://tenant-admin.sharepoint.com/` work
- **Improved URL handling**: Added automatic trimming of trailing slashes before passing to compliance script

### Technical Details
- Updated regex pattern from `^https://.*-admin\.sharepoint\.com$` to `^https://.*-admin\.sharepoint\.com/?$`
- Added `TrimEnd('/')` to clean URLs before processing

### Issue Reported
User reported error when using tab-completion which adds trailing slash to SharePoint URLs.

## [2.1.0] - 2025-01-13

### 🚀 Major Update - Module Command Support

This is a **breaking change** release that restructures the project as a proper PowerShell module with exported cmdlets.

### ✨ Added
- **PowerShell Module Structure**: Module now exports proper cmdlets instead of requiring direct script execution
- **New Commands**:
  - `Invoke-CISBenchmark` - Main cmdlet to run compliance checks with full parameter support
  - `Get-CISBenchmarkControl` - Query information about specific CIS controls
  - `Test-CISBenchmarkPrerequisites` - Verify all required PowerShell modules are installed
  - `Get-CISBenchmarkInfo` - Display module information and quick start guide
- **Enhanced Parameter Support**: Better validation and help documentation for all parameters
- **Verbose Logging**: Support for `-Verbose` switch to see detailed execution progress
- **Summary Output**: `Invoke-CISBenchmark` returns a PSCustomObject with compliance statistics

### 🔧 Changed
- **Breaking**: Module structure changed from script-only to proper PSM1/PSD1 module
- **Breaking**: After installing from PowerShell Gallery, use `Invoke-CISBenchmark` instead of running `.ps1` file
- Updated `ModuleVersion` from 2.0.0 to 2.1.0
- Updated README.md with module command usage examples
- Script execution logic now only runs when called directly, not when dot-sourced

### 🐛 Fixed
- Fixed module loading errors when importing from PowerShell Gallery
- Fixed mandatory parameter validation errors during module import
- Script no longer auto-executes when imported as module dependency

### 📝 Documentation
- Added comprehensive comment-based help for all exported functions
- Updated README with module command examples
- Added "Legacy Script Usage" section for backward compatibility
- Enhanced inline documentation with better examples

### 💡 Usage Examples

After installation:
```powershell
# Import module
Import-Module CIS-M365-Benchmark

# See available commands
Get-Command -Module CIS-M365-Benchmark

# Run compliance check
Invoke-CISBenchmark -TenantDomain "tenant.onmicrosoft.com" `
                    -SharePointAdminUrl "https://tenant-admin.sharepoint.com"

# Check prerequisites
Test-CISBenchmarkPrerequisites

# Get module info
Get-CISBenchmarkInfo
```

### 🔄 Migration Guide

**For PowerShell Gallery users:**
```powershell
# Old way (v2.0.0) - NO LONGER WORKS
Install-Module CIS-M365-Benchmark
# Then manually find and run .ps1 file (confusing!)

# New way (v2.1.0)
Install-Module CIS-M365-Benchmark
Import-Module CIS-M365-Benchmark
Invoke-CISBenchmark -TenantDomain "tenant.onmicrosoft.com" `
                    -SharePointAdminUrl "https://tenant-admin.sharepoint.com"
```

**For direct script users:**
- No changes required - script can still be run directly:
  ```powershell
  .\CIS-M365-Compliance-Checker.ps1 -TenantDomain "..." -SharePointAdminUrl "..."
  ```

## [2.0.0] - 2025-01-11

### 🚀 Major Release - Significant Automation Improvements

### Added
- ✨ **25+ New Automated Checks** - Increased automation coverage from ~35% to 68%
- 📊 **Section 4: Intune Checks** - Automated device compliance and enrollment restrictions
- 🔐 **Section 5.3: PIM & Governance** - Full automation of Privileged Identity Management checks
- 🎯 **Enhanced CA Policy Checks** - Automated detection of Conditional Access policies
- 🔑 **Authentication Method Automation** - MFA fatigue protection, weak auth detection
- 📈 **Access Reviews Automation** - Automated checks for guest and privileged role reviews
- 📝 **Comprehensive Documentation** - Added PERMISSIONS.md with detailed permission requirements

### Automated Checks (New in v2.0)

#### Section 1: M365 Admin Center
- 1.3.1: Password expiration policy validation

#### Section 4: Microsoft Intune
- 4.1: Device compliance policy settings
- 4.2: Personal device enrollment restrictions

#### Section 5: Entra ID
- 5.1.2.2: Third-party app registration restrictions
- 5.1.2.4: Entra admin center access controls
- 5.2.2.10: Managed device requirement for MFA registration
- 5.2.2.11: Intune enrollment sign-in frequency
- 5.2.3.1: Microsoft Authenticator MFA fatigue protection
- 5.2.3.2: Custom banned password lists
- 5.2.3.5: Weak authentication methods (SMS/Voice) detection
- 5.2.3.6: System-preferred MFA configuration
- 5.2.4.1: Self-service password reset (SSPR) validation
- 5.3.1: Privileged Identity Management (PIM) configuration
- 5.3.2: Access reviews for guest users
- 5.3.3: Access reviews for privileged roles
- 5.3.4: Global Administrator approval requirements
- 5.3.5: Privileged Role Administrator approval requirements

#### Section 6: Exchange Online
- 6.1.2: Mailbox audit actions configuration

#### Section 7: SharePoint Online
- 7.3.2: OneDrive sync restrictions for unmanaged devices
- 7.3.3: Custom script execution restrictions on personal sites

#### Section 8: Microsoft Teams
- 8.4.1: Teams app permission policies

### Fixed
- 🐛 **1.2.1**: Fixed Get-MgGroup visibility filter error (unsupported query)
- 🐛 **3.2.1 & 3.2.2**: Fixed DLP policy cmdlet errors with graceful fallback
- 🐛 **6.1.3**: Fixed mailbox audit bypass check using correct cmdlet
- 🔧 **MSOnline Connection**: Made optional with graceful degradation
- 🔧 **Multiple Sign-ins**: Improved session reuse with TenantId parameter

### Changed
- ⚡ **Performance**: Reduced manual checks from 44% to 25-27%
- 📊 **Automation Coverage**: Increased from ~35-38% to 68%
- 🎨 **Logging**: Enhanced progress logging with better status messages
- 🔐 **Error Handling**: Improved try-catch blocks with graceful fallbacks
- 📝 **Remediation Steps**: Added detailed remediation for all automated checks

### Performance Metrics

| Metric | v1.0 | v2.0 | Improvement |
|--------|------|------|-------------|
| Total Controls | 130 | 130 | - |
| Automated | ~45-50 | ~89 | +78% |
| Manual | ~57 | ~41 | -28% |
| Errors | ~3 | ~0-1 | -67% |
| Coverage | 35-38% | 68% | +80% |

## [1.0.0] - 2025-01-10

### Initial Release

### Added
- ✅ Complete CIS Microsoft 365 Foundations Benchmark v5.0.0 coverage
- ✅ 130 compliance controls across 9 sections
- ✅ HTML and CSV report generation
- ✅ Microsoft Graph API integration
- ✅ Exchange Online compliance checks
- ✅ SharePoint Online security validation
- ✅ Microsoft Teams configuration assessment
- ✅ Basic Entra ID (Azure AD) checks
- ✅ Microsoft 365 Defender security controls
- ✅ Microsoft Purview audit and DLP checks

### Supported Sections
1. Microsoft 365 Admin Center (8 controls)
2. Microsoft 365 Defender (14 controls)
3. Microsoft Purview (3 controls)
4. Microsoft Intune Admin Center (2 controls)
5. Microsoft Entra Admin Center (41 controls)
6. Exchange Admin Center (14 controls)
7. SharePoint Admin Center (14 controls)
8. Microsoft Teams Admin Center (13 controls)
9. Microsoft Fabric / Power BI (11 controls)

### Known Limitations (v1.0)
- High percentage of manual checks (~44%)
- MSOnline connection issues
- Some Graph API filter errors
- DLP cmdlet availability issues

---

## Version History

- **v2.0.0** (2025-01-11) - Major automation improvements, 68% coverage
- **v1.0.0** (2025-01-10) - Initial release, 35-38% coverage

## Upgrade Guide

### From v1.0 to v2.0

No breaking changes. Simply replace the script file and run as before:

```powershell
# Download latest version
git pull origin main

# Run with same parameters as before
.\CIS-M365-Compliance-Checker.ps1 `
    -TenantDomain "your-tenant.onmicrosoft.com" `
    -SharePointAdminUrl "https://your-tenant-admin.sharepoint.com"
```

### New Permissions Required (v2.0)

The following additional Graph API permissions are now utilized:
- `RoleManagement.Read.All` (for PIM checks)
- Access to beta endpoints for advanced features

No action required if using Global Reader role - this already includes these permissions.

## Future Roadmap

### Planned for v2.1
- [ ] Certificate-based authentication for automation
- [ ] Power BI module integration for Section 9
- [ ] Custom report templates
- [ ] Compliance trend tracking over time
- [ ] Email report delivery

### Planned for v3.0
- [ ] Remediation automation (fix failed controls)
- [ ] Drift detection (compare against baseline)
- [ ] Integration with Azure DevOps pipelines
- [ ] Custom control definitions
- [ ] Multi-tenant support

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## Support

- 🐛 [Report bugs](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues)
- 💡 [Request features](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/issues)
- 💬 [Ask questions](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark/discussions)
