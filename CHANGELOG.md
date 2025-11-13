# Changelog

All notable changes to the CIS Microsoft 365 Foundations Benchmark Compliance Checker will be documented in this file.

## [2.3.1] - 2025-01-13

### Critical Fix - Microsoft.Graph Version Check Timing

**FIXED: Microsoft.Graph version check now happens BEFORE auto-detection!**

This patch release fixes a critical bug in v2.3.0 where the Microsoft.Graph version check happened AFTER the auto-detection logic, causing authentication failures when old versions (< 2.0.0) were present.

### What Was Broken in v2.3.0

When running `Invoke-CISBenchmark` with zero parameters:
1. Auto-detection tried to connect to Microsoft Graph FIRST
2. If old Microsoft.Graph (< 2.0.0) was installed, authentication failed
3. Error: `InteractiveBrowserCredential authentication failed: Method not found: Microsoft.Identity.Client.BaseAbstractApplicationBuilder`
4. Only AFTER the failure would the version check run
5. User had to restart PowerShell and run command again

### What's Fixed in v2.3.1

✅ **Execution Order Fixed**:
```
OLD (v2.3.0):
1. Auto-detection (fails if old Graph version)
2. Microsoft.Graph version check (too late!)

NEW (v2.3.1):
1. Microsoft.Graph version check (happens FIRST)
2. Auto-detection (uses updated Graph version)
```

✅ **Better User Experience**:
- Clear message: "This requires authentication to retrieve your tenant information"
- Friendly prompt: "Please sign in to Microsoft 365..." instead of generic "Authenticating..."
- Authentication is now explained upfront

### User Experience - Before and After

**Before (v2.3.0 with old Microsoft.Graph):**
```powershell
PS> Invoke-CISBenchmark

================================================================
  Auto-Detecting Microsoft 365 Tenant Information
================================================================

Connecting to Microsoft Graph to detect tenant...
Authenticating to Microsoft Graph...

Failed to auto-detect tenant information: InteractiveBrowserCredential authentication failed: Method not found...
```

**After (v2.3.1):**
```powershell
PS> Invoke-CISBenchmark

[Checks Microsoft.Graph version first]
[Updates if needed, prompts to restart]

================================================================
  Auto-Detecting Microsoft 365 Tenant Information
================================================================

Connecting to Microsoft Graph to detect tenant...
(This requires authentication to retrieve your tenant information)

Please sign in to Microsoft 365...
[Browser opens - authentication succeeds]

  Detected Tenant Domain: contoso.onmicrosoft.com
  Detected SharePoint Admin URL: https://contoso-admin.sharepoint.com
```

### Technical Changes

- Moved `Script:Fix-MicrosoftGraphVersion` call to line 354 (before auto-detection)
- Removed duplicate version check that was happening after auto-detection
- Added user-friendly authentication messages
- Zero-parameter usage now works correctly with any Microsoft.Graph version

### Recommendation

If you installed v2.3.0 and encountered the Microsoft.Graph authentication error:
1. Update to v2.3.1: `Update-Module CIS-M365-Benchmark`
2. Restart PowerShell (if Microsoft.Graph was updated)
3. Run: `Invoke-CISBenchmark` (should work now!)

## [2.3.0] - 2025-01-13

### Major Feature - Zero-Parameter Usage (Like Microsoft ZeroTrustAssessment!)

**YOU CAN NOW JUST RUN: `Invoke-CISBenchmark`**

No parameters required! The module works exactly like Microsoft's ZeroTrustAssessment module.

### New Features

- **Auto-Detection of Tenant Information**: Module automatically detects your M365 tenant domain and SharePoint admin URL
- **Zero-Parameter Usage**: Simply run `Invoke-CISBenchmark` without any parameters
- **Microsoft Graph Integration**: Connects to Graph API and retrieves organization details
- **Intelligent URL Construction**: Automatically builds SharePoint admin URL from tenant name
- **Backwards Compatible**: Manual parameters still work for explicit control

### Usage - Before and After

**Before (v2.2.5):**
```powershell
Invoke-CISBenchmark -TenantDomain "contoso.onmicrosoft.com" `
                    -SharePointAdminUrl "https://contoso-admin.sharepoint.com"
```

**Now (v2.3.0):**
```powershell
Invoke-CISBenchmark  # That's it!
```

### How Auto-Detection Works

1. When you run `Invoke-CISBenchmark` without parameters
2. Module connects to Microsoft Graph with `Organization.Read.All` scope
3. Retrieves organization details via `Get-MgOrganization`
4. Extracts `*.onmicrosoft.com` domain as tenant domain
5. Constructs SharePoint admin URL: `https://<tenant>-admin.sharepoint.com`
6. Runs compliance assessment with auto-detected information

### User Experience

```powershell
PS> Invoke-CISBenchmark

================================================================
  Auto-Detecting Microsoft 365 Tenant Information
================================================================

Connecting to Microsoft Graph to detect tenant...
  Detected Tenant Domain: contoso.onmicrosoft.com
  Detected SharePoint Admin URL: https://contoso-admin.sharepoint.com

[Assessment continues automatically...]
```

### Benefits

- **Faster**: No need to look up tenant information
- **Easier**: One command does everything
- **Error-Proof**: No typos in domains or URLs
- **Professional**: Works like Microsoft's official tools (ZeroTrustAssessment, Secure Score)
- **User-Friendly**: Perfect for both beginners and automation

### Fallback Behavior

If auto-detection fails (network issues, permissions), clear error message with manual parameter instructions:
```
Failed to auto-detect tenant information: <error>

Please provide the tenant information manually:
  Invoke-CISBenchmark -TenantDomain 'tenant.onmicrosoft.com' -SharePointAdminUrl 'https://tenant-admin.sharepoint.com'
```

### Technical Implementation

- `TenantDomain` and `SharePointAdminUrl` parameters now optional (`Mandatory=$false`)
- Auto-detection logic in `begin` block before Microsoft.Graph version check
- Uses `Get-MgContext` to check existing connection before connecting
- Graceful error handling with helpful user guidance
- Updated help documentation with new zero-parameter examples

### Backwards Compatibility

**100% backwards compatible!** All existing scripts continue to work:
```powershell
# Still works perfectly
Invoke-CISBenchmark -TenantDomain "contoso.onmicrosoft.com" `
                    -SharePointAdminUrl "https://contoso-admin.sharepoint.com"
```

## [2.2.5] - 2025-01-13

### Critical Fix - Aggressive Microsoft.Graph Auto-Update

- **BREAKING THROUGH**: Forcefully uninstalls ALL outdated Microsoft.Graph versions (< 2.0.0) before importing
- **Module Load Guarantee**: Module ALWAYS loads successfully, even if Microsoft.Graph is completely broken
- **Import-Time Fix**: Microsoft.Graph version checked and fixed during Import-Module, not delayed until Invoke
- **Detailed Progress**: Shows each version being uninstalled with progress feedback

### What This Fixes

User-reported critical issue in v2.2.4:
```
PS> Install-Module -Name CIS-M365-Benchmark -RequiredVersion 2.2.4
PS> Import-Module CIS-M365-Benchmark
PS> Invoke-CISBenchmark
Invoke-CISBenchmark : The term 'Invoke-CISBenchmark' is not recognized
```

Root cause: Module failed to export functions when Microsoft.Graph import failed during module load.

### How v2.2.5 Fixes It

1. **During Import-Module**: Detects Microsoft.Graph < 2.0.0
2. **Aggressive Cleanup**: Uninstalls EACH old version individually with progress
3. **Fresh Install**: Installs latest Microsoft.Graph from PowerShell Gallery
4. **Always Exports**: Module functions exported even if Microsoft.Graph import fails
5. **User Can Proceed**: Invoke-CISBenchmark is always available

### Tested Scenarios

- Fresh install with no Microsoft.Graph installed
- Old Microsoft.Graph v1.x installed (most common issue)
- Multiple old versions installed
- Broken/corrupted Microsoft.Graph installation

All scenarios now work correctly - module loads and functions are available.

### Technical Details

- Enhanced Install-PrerequisitesAutomatically with special Microsoft.Graph handling
- Uses Get-InstalledModule to find ALL versions, then Uninstall-Module for each
- Installs latest stable version with -Force -AllowClobber flags
- Non-blocking imports ensure module loads even if update fails

## [2.2.4] - 2025-01-13

### Critical Fixes - Microsoft.Graph Auto-Update & Module Resilience

- **Microsoft.Graph Auto-Update**: Now properly detects and updates outdated versions at runtime
- **Module Loading Resilience**: Module now loads successfully even if Microsoft.Graph import fails
- **Version Check on Invoke**: Automatically checks and fixes Microsoft.Graph version when running Invoke-CISBenchmark
- **Force Import**: Added -Force flag to module imports to ensure fresh load and prevent stale versions

### What This Fixes

User-reported issues in v2.2.3:
1. **PowerShell 7**: `Method not found: Microsoft.Identity.Client.BaseAbstractApplicationBuilder` error during authentication
2. **PowerShell 5**: Module fails to load completely after Microsoft.Graph import warning - `invoke-cisbenchmark is not recognized`

### How It Works Now

1. Module imports successfully even if Microsoft.Graph has issues (non-blocking imports)
2. When you run `Invoke-CISBenchmark`, it automatically checks Microsoft.Graph version before running compliance checks
3. If version < 2.0.0 detected, it removes old versions and installs latest compatible version
4. Prompts you to restart PowerShell for changes to take effect

### Manual Fix (if auto-update doesn't work)

If the automatic update doesn't resolve the issue:
```powershell
Get-InstalledModule Microsoft.Graph -AllVersions | Uninstall-Module -Force
Install-Module Microsoft.Graph -Force -AllowClobber
```

Then restart PowerShell and run Invoke-CISBenchmark again.

### Technical Details

- Changed module import behavior to non-blocking with graceful error handling
- Added `Fix-MicrosoftGraphVersion` internal function that runs before compliance checks
- Module exports successfully even if prerequisite imports fail during module load
- Added -Force flag to all Import-Module calls to prevent cached module issues

## [2.2.3] - 2025-01-13

### ✨ Enhancements - PowerShell Compatibility & Auto-Update

- **Full PowerShell 5.1 & 7+ Support**: Enhanced compatibility for both PowerShell Desktop (5.1) and Core (7+)
- **Automatic Dependency Updates**: Outdated modules now automatically update during module import
- **Version Checking**: Ensures Microsoft.Graph 2.0+ to prevent authentication errors
- **Smart Module Loading**: Detects PowerShell edition and uses appropriate import flags

### 🐛 Bug Fixes

- **Fixed**: Microsoft.Graph authentication errors caused by version conflicts
- **Fixed**: `Method not found: Microsoft.Identity.Client.BaseAbstractApplicationBuilder` error
- **Fixed**: Module import failures on PowerShell 7 with `-SkipEditionCheck` flag
- **Improved**: Module version detection now uses latest installed version

### 🔧 Technical Improvements

- Added minimum version requirements for Microsoft.Graph (2.0.0+)
- Automatic `Update-Module` for outdated dependencies
- PowerShell version detection (Desktop vs Core) with appropriate import flags
- Shows PowerShell version during prerequisite installation for debugging
- Graceful fallback to reinstall if update fails

### 💡 User Experience

- More informative console output showing PowerShell edition
- Better error messages when module updates fail
- Automatic compatibility fixes without user intervention
- Existing installations will automatically upgrade dependencies on next import

### What This Fixes

User reported error:
```
InteractiveBrowserCredential authentication failed: Method not found:
'!0 Microsoft.Identity.Client.BaseAbstractApplicationBuilder`1.WithLogging(...)
```

This was caused by an outdated Microsoft.Graph module. v2.2.3 automatically detects and updates to a compatible version.

## [2.2.2] - 2025-01-13

### 🐛 Bug Fix - Module Import Issue
- **Fixed**: Prerequisite modules are now automatically imported after installation
- **Fixed**: SharePoint cmdlets (Connect-SPOService) now properly available
- **Fixed**: All required modules loaded into session automatically
- **Improved**: Faster module loading with `-DisableNameChecking` flag
- **Improved**: Better error handling for module import failures

### What Changed
- Modules are automatically installed AND imported when CIS-M365-Benchmark loads
- Progress feedback shows which modules are being loaded
- Fixes "cmdlet not recognized" errors for SharePoint, Teams, and Exchange
- No user action required - everything works seamlessly

### Technical Details
- Added automatic module import after installation
- Prerequisite modules are loaded silently with warning suppression
- Import failures are handled gracefully without blocking module load

## [2.2.1] - 2025-01-13

### ✨ New Features - FULLY AUTOMATIC INSTALLATION
- **Zero-Configuration Setup**: All prerequisite modules install automatically when you import CIS-M365-Benchmark!
- **No User Prompts**: Completely silent installation with visual progress feedback
- **Auto-Installs 5 Required Modules**:
  - Microsoft.Graph
  - ExchangeOnlineManagement
  - Microsoft.Online.SharePoint.PowerShell
  - MicrosoftTeams
  - MSOnline

### 🔧 Improved User Experience
- **Two-Step Installation**: Just `Install-Module` → `Invoke-CISBenchmark` (that's it!)
- **No Manual Steps**: No need to run separate installation commands
- **Progress Feedback**: See each module install with checkmarks
- **Ready to Use**: Module is fully functional immediately after first import

### 💡 Simplified Usage Flow

The simplest installation experience ever:

```powershell
# Step 1: Install the module
Install-Module -Name CIS-M365-Benchmark -Scope CurrentUser

# Step 2: Run compliance check (automatically imports module and installs prerequisites)
Invoke-CISBenchmark -TenantDomain "contoso.onmicrosoft.com" `
                    -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

# Behind the scenes on first run:
# ═══════════════════════════════════════════════════════════════
#   CIS M365 Benchmark - Auto-Installing Prerequisites
# ═══════════════════════════════════════════════════════════════
#
# Installing 2 missing module(s)...
#
#   Installing Microsoft.Online.SharePoint.PowerShell... ✓
#   Installing MSOnline... ✓
#
# ═══════════════════════════════════════════════════════════════
#   Prerequisites installation complete!
# ═══════════════════════════════════════════════════════════════
```

### Technical Details
- Added automatic prerequisite installation in PSM1 module initialization
- Uses `Install-Module -Force -AllowClobber -Scope CurrentUser`
- Runs once per session when module is first imported
- Silent operation with `-WarningAction SilentlyContinue`
- Internal function: `Script:Install-PrerequisitesAutomatically`
- No performance impact after first import

### Breaking Changes
- None - existing workflows continue to work
- `Install-CISBenchmarkPrerequisites` command still available for manual installation if needed

## [2.2.0] - 2025-01-13

### ✨ New Features
- **Dependency Installation Helper**: Added `Install-CISBenchmarkPrerequisites` command
  - Automatically installs missing required PowerShell modules
  - Interactive prompts with progress feedback
  - Supports `-Force` switch for non-interactive installation
  - Supports `-Scope` parameter (CurrentUser or AllUsers)
  - Gracefully handles installation failures with clear error messages

### 🔧 Improved User Experience
- **Easier Setup**: Users no longer need to manually install 6+ prerequisite modules
- **Clear Feedback**: Installation progress shown for each module
- **Flexible Installation**: Choose installation scope (CurrentUser or AllUsers)
- **Non-Interactive Mode**: Use `-Force` for automated deployments

### 💡 Usage Examples

After installing the module, check and install prerequisites:
```powershell
# Import module
Import-Module CIS-M365-Benchmark

# Check which modules are missing
Test-CISBenchmarkPrerequisites

# Install missing modules interactively
Install-CISBenchmarkPrerequisites

# Install without prompts (for automation)
Install-CISBenchmarkPrerequisites -Force

# Install for all users (requires admin)
Install-CISBenchmarkPrerequisites -Scope AllUsers
```

### Technical Details
- New exported function: `Install-CISBenchmarkPrerequisites`
- Integrated with existing `Test-CISBenchmarkPrerequisites` for status checks
- Uses PowerShell Gallery's `Install-Module` with error handling
- Skips installation if all modules already present

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

- 🐛 [Report bugs](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💡 [Request features](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues)
- 💬 [Ask questions](https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/discussions)
