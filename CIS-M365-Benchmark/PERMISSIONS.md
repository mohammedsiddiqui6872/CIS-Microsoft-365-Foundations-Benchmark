# Required Permissions for CIS M365 Compliance Checker

This document details all permissions required to run the CIS Microsoft 365 Foundations Benchmark Compliance Checker script.

## Overview

The script requires **read-only** permissions across multiple Microsoft 365 services. No write or modify permissions are needed.

## Microsoft Graph API Permissions

The script uses the following Microsoft Graph API scopes:

| Permission | Type | Purpose |
|------------|------|---------|
| `Directory.Read.All` | Delegated | Read directory data (users, groups, roles) |
| `Policy.Read.All` | Delegated | Read organization policies (Conditional Access, etc.) |
| `AuditLog.Read.All` | Delegated | Read audit log data |
| `UserAuthenticationMethod.Read.All` | Delegated | Read user authentication methods (MFA settings) |
| `IdentityRiskyUser.Read.All` | Delegated | Read risky user information |
| `IdentityRiskEvent.Read.All` | Delegated | Read risk detection information |
| `Application.Read.All` | Delegated | Read application registrations |
| `Organization.Read.All` | Delegated | Read organization information |
| `User.Read.All` | Delegated | Read all user profiles |
| `Group.Read.All` | Delegated | Read all groups |
| `RoleManagement.Read.All` | Delegated | Read role assignments and definitions |
| `Reports.Read.All` | Delegated | Read usage reports |

### How to Grant Graph Permissions

**Option 1: Interactive (User Consent)**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All"
# User will be prompted to consent on first run
```

**Option 2: Admin Consent (Recommended for Enterprise)**
1. Go to Azure Portal > Azure Active Directory > App Registrations
2. Create a new app registration or use existing
3. Add API Permissions > Microsoft Graph > Delegated Permissions
4. Add all permissions listed above
5. Click "Grant admin consent for [Tenant]"

## Azure AD / Entra ID Roles

Your account needs **at least one** of the following roles:

### Minimum Required Role
- **Global Reader** ✅ (Recommended - Read-only access to everything)

### Alternative Roles (if Global Reader not available)
- **Security Reader** + **Compliance Administrator**
- **Security Administrator** + **Compliance Administrator**
- **Global Administrator** (Not recommended - too much access)

## Exchange Online Permissions

| Role | Required | Purpose |
|------|----------|---------|
| **View-Only Organization Management** | Yes | Read Exchange configuration |
| **View-Only Recipients** | Yes | Read mailbox settings |
| **Security Reader** | Optional | Additional Exchange security settings |

### How to Assign Exchange Roles

**Via Exchange Admin Center:**
1. Go to Exchange Admin Center > Roles > Admin roles
2. Select "View-Only Organization Management"
3. Add your admin account to Members

**Via PowerShell:**
```powershell
Connect-ExchangeOnline
Add-RoleGroupMember -Identity "View-Only Organization Management" -Member "admin@contoso.com"
```

## SharePoint Online Permissions

| Role | Required | Purpose |
|------|----------|---------|
| **SharePoint Administrator** | Yes | Read SharePoint tenant settings |
| **Global Reader** | Alternative | Can also read SharePoint settings |

### How to Assign SharePoint Roles

1. Go to Microsoft 365 Admin Center > Users > Active users
2. Select the user > Roles
3. Assign "SharePoint Administrator" role

## Microsoft Teams Permissions

| Role | Required | Purpose |
|------|----------|---------|
| **Teams Administrator** | Yes | Read Teams policies and settings |
| **Global Reader** | Alternative | Can also read Teams settings |

### How to Assign Teams Roles

1. Go to Microsoft 365 Admin Center > Users > Active users
2. Select the user > Roles
3. Assign "Teams Administrator" role

## Microsoft Intune Permissions

| Permission | Required | Purpose |
|------------|----------|---------|
| **Intune Read-Only Operator** | Yes | Read device compliance policies |
| **Global Reader** | Alternative | Can also read Intune settings |

### How to Grant Intune Permissions

**Via Endpoint Manager:**
1. Go to Microsoft Endpoint Manager admin center
2. Tenant administration > Roles
3. Assign "Intune Read-Only Operator" role

**Via Azure AD:**
1. Azure Portal > Azure Active Directory > Users
2. Select user > Assigned roles
3. Add "Intune Service Administrator" (if read-only not available)

## Microsoft Purview / Compliance Permissions

| Role | Required | Purpose |
|------|----------|---------|
| **Compliance Administrator** | Recommended | Full access to compliance features |
| **Compliance Data Administrator** | Alternative | Read compliance data |
| **Security Reader** | Minimum | Read-only security and compliance |

### DLP Policy Access
For DLP checks, you need:
- **Security & Compliance Center** access
- PowerShell connection to Security & Compliance

```powershell
Connect-IPPSSession  # Information Protection and Compliance
```

## Microsoft Fabric / Power BI Permissions

| Role | Required | Purpose |
|------|----------|---------|
| **Power BI Administrator** | Yes | Read Power BI tenant settings |
| **Fabric Administrator** | Alternative | Full access to Fabric/Power BI settings |

### How to Assign Power BI Roles
1. Go to Microsoft 365 Admin Center > Users > Active users
2. Select the user > Roles
3. Assign "Power BI Administrator" or "Fabric Administrator" role

## MSOnline (Legacy) - Optional

The script attempts to connect to MSOnline for legacy per-user MFA checks.

| Module | Status | Purpose |
|--------|--------|---------|
| MSOnline | Optional | Check per-user MFA settings (deprecated) |

**Note**: If MSOnline connection fails, the script continues and marks control 5.1.2.1 as "Manual". This is expected behavior as Microsoft is deprecating this module.

## Complete Role Assignment Example

### Recommended: Single "Global Reader" Role

```powershell
# Assign Global Reader role (read-only access to everything)
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

$user = Get-MgUser -UserId "admin@contoso.com"
$roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Reader'"

New-MgRoleManagementDirectoryRoleAssignment `
    -PrincipalId $user.Id `
    -RoleDefinitionId $roleDefinition.Id `
    -DirectoryScopeId "/"
```

### Alternative: Granular Permissions

If Global Reader is not available, assign these specific roles:

```powershell
# Roles to assign:
# - Security Reader
# - Compliance Administrator
# - SharePoint Administrator (or read-only)
# - Teams Administrator (or read-only)
# - Exchange Administrator (View-Only Organization Management)
# - Intune Read-Only Operator
# - Power BI Administrator
```

## Service-Specific Connection Commands

### Microsoft Graph
```powershell
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All", `
                       "UserAuthenticationMethod.Read.All", "IdentityRiskyUser.Read.All", `
                       "Application.Read.All", "Organization.Read.All", "User.Read.All", `
                       "Group.Read.All", "RoleManagement.Read.All", "Reports.Read.All"
```

### Exchange Online
```powershell
Connect-ExchangeOnline -UserPrincipalName "admin@contoso.com"
```

### SharePoint Online
```powershell
Connect-SPOService -Url "https://contoso-admin.sharepoint.com"
```

### Microsoft Teams
```powershell
Connect-MicrosoftTeams
```

### Security & Compliance (for DLP)
```powershell
Connect-IPPSSession
```

### Power BI / Microsoft Fabric
```powershell
Connect-PowerBIServiceAccount
```

## Testing Your Permissions

Before running the full compliance check, test your permissions:

```powershell
# Test Graph API access
Connect-MgGraph
Get-MgOrganization
Get-MgUser -Top 1

# Test Exchange access
Connect-ExchangeOnline
Get-OrganizationConfig

# Test SharePoint access
Connect-SPOService -Url "https://yourtenant-admin.sharepoint.com"
Get-SPOTenant

# Test Teams access
Connect-MicrosoftTeams
Get-CsTenant

# Test Power BI access
Connect-PowerBIServiceAccount
Invoke-PowerBIRestMethod -Url "admin/tenantsettings" -Method GET
```

If all commands return data without errors, you have the necessary permissions.

## Permission Troubleshooting

### Error: "Insufficient privileges to complete the operation"
- **Solution**: Ensure you have Global Reader or equivalent role
- Verify role assignments in Azure AD > Users > [Your User] > Assigned roles

### Error: "Access denied" when connecting to service
- **Solution**: Add your account to the appropriate admin role group
- Wait 5-10 minutes for permission changes to propagate

### Error: "Admin consent required"
- **Solution**: Have a Global Administrator grant admin consent for Graph API permissions
- Azure Portal > App Registrations > [Your App] > API Permissions > Grant admin consent

### Error: "The term 'Get-DlpCompliancePolicy' is not recognized"
- **Solution**: This is normal if Security & Compliance PowerShell is not connected
- The script will mark DLP checks as "Manual" and continue

## Security Best Practices

1. ✅ **Use a dedicated compliance account** - Don't use your day-to-day admin account
2. ✅ **Enable MFA** - Always protect admin accounts with multi-factor authentication
3. ✅ **Use Privileged Identity Management (PIM)** - Activate roles just-in-time when needed
4. ✅ **Regular access reviews** - Review who has access to run compliance checks
5. ✅ **Audit logging** - Enable audit logging for all privileged operations
6. ✅ **Principle of least privilege** - Use Global Reader instead of Global Administrator

## Automated/Unattended Execution

For automated compliance checking (e.g., scheduled tasks), use **certificate-based authentication**:

### Setup Certificate Authentication

1. **Create app registration** in Azure AD
2. **Generate certificate**:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=M365ComplianceChecker" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable `
       -KeySpec Signature `
       -KeyLength 2048 `
       -NotAfter (Get-Date).AddYears(2)
   ```
3. **Upload certificate** to app registration
4. **Grant API permissions** to the app
5. **Connect using certificate**:
   ```powershell
   Connect-MgGraph -ClientId "app-id" `
                   -TenantId "tenant-id" `
                   -CertificateThumbprint "cert-thumbprint"
   ```

## Summary Checklist

Before running the script, ensure you have:

- [ ] Global Reader role (or equivalent granular roles)
- [ ] Microsoft Graph API permissions granted
- [ ] Exchange Online View-Only Organization Management
- [ ] SharePoint Administrator (or Global Reader)
- [ ] Teams Administrator (or Global Reader)
- [ ] Intune Read-Only Operator (if using Intune)
- [ ] Power BI Administrator (for Section 9 checks)
- [ ] All PowerShell modules installed
- [ ] Network access to Microsoft 365 endpoints
- [ ] MFA configured on your account
- [ ] Permissions tested using the commands above

---

For questions about permissions, please open an issue on GitHub or consult the [Microsoft 365 documentation](https://docs.microsoft.com/en-us/microsoft-365/).