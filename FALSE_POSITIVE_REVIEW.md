# CIS M365 Benchmark v2.4.3 - Comprehensive False Positive Review

## Review Date: 2025-01-17
## Reviewer: Automated Analysis + User-Reported Issues
## Module Version: 2.4.3

---

## RECENTLY FIXED (v2.4.3)

### ✅ Control 5.2.3.1 - Microsoft Authenticator MFA Fatigue Protection
**Issue**: False positive when number matching was set to "default" instead of "enabled"
**User Report**: Control failed showing "Number matching: not configured, App context: enabled"
**Root Cause**:
1. Microsoft changed number matching to be "on by default" in 2025
2. Graph API returns state as "default" when using Microsoft's baseline (which is now enabled)
3. Previous code only accepted "enabled" as compliant, rejecting "default"
4. Missing third required check: `displayLocationInformationRequiredState`

**Fix Applied**:
- Updated validation to accept BOTH "enabled" AND "default" as compliant states
- Added missing third check for geographic location display (`displayLocationInformationRequiredState`)
- CIS 5.2.3.1 requires THREE settings all enabled:
  1. `numberMatchingRequiredState` - Require number matching for push notifications
  2. `displayAppInformationRequiredState` - Show application name in notifications
  3. `displayLocationInformationRequiredState` - Show geographic location in notifications
- Enhanced details output to show all three states for better troubleshooting
- Updated remediation guidance to list all three required settings

**Impact**: ELIMINATED FALSE POSITIVE - Now correctly passes when number matching is set to Microsoft's default (enabled) state

**Code Changes** (lines 1698-1762):
```powershell
# Before: Only checked 2 settings, only accepted "enabled"
if ($numberMatching -eq "enabled" -and $additionalContext -eq "enabled")

# After: Checks all 3 settings, accepts "enabled" or "default"
$numberMatchingCompliant = ($numberMatching -eq "enabled" -or $numberMatching -eq "default")
$additionalContextCompliant = ($additionalContext -eq "enabled" -or $additionalContext -eq "default")
$locationContextCompliant = ($locationContext -eq "enabled" -or $locationContext -eq "default")

if ($numberMatchingCompliant -and $additionalContextCompliant -and $locationContextCompliant)
```

**References**:
- Microsoft documentation: "As the 'Require number matching for push notifications' setting is now on by default"
- CIS Benchmark v5.0.0: Requires all three settings enabled

---

## POTENTIAL ISSUES IDENTIFIED

### HIGH PRIORITY

#### 1. Control 5.1.5.1 - User Consent to Apps (L2)
**Issue**: Incomplete validation logic
**Current Check**: Only verifies if "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" is in the PermissionGrantPoliciesAssigned array
**Problem**:
- Does NOT check if the array is empty (which means consent is disabled)
- Does NOT check if user consent is enabled via OTHER permission grant policies
- Should PASS when array is empty OR doesn't contain the legacy policy
- Should FAIL only when it contains policies that allow user consent

**Impact**: Could show FALSE NEGATIVE (misses when consent is enabled via other policies)

**Recommendation**:
```powershell
# Should check:
if ($authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned.Count -eq 0 -or
    -not ($authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned -contains "ManagePermissionGrantsForSelf.microsoft-user-default-legacy")) {
    # PASS - User consent disabled
} else {
    # FAIL - User consent may be enabled
}
```

---

#### 2. Control 5.2.2.1 - MFA for Administrative Roles (L1)
**Issue**: Does not validate WHICH admin roles are included
**Current Check**: Only verifies that `$policy.Conditions.Users.IncludeRoles` is not null/empty
**Problem**:
- A policy with MFA that only targets ONE admin role would PASS
- CIS Benchmark requires MFA for ALL administrative roles
- Should verify that ALL critical admin roles are covered

**Impact**: FALSE POSITIVE (passes when not all admin roles are protected)

**Recommendation**:
```powershell
# Should check if policy includes "All directory roles" or at minimum:
$criticalRoles = @(
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    # ... other critical roles
)
# Verify policy targets these roles or uses "All directory roles"
```

---

#### 3. Control 5.2.2.2 - MFA for All Users (L1)
**Issue**: Same as 5.2.2.1 - doesn't validate targeting
**Current Check**: Only checks if policy includes "All" users and requires MFA
**Problem**:
- Does NOT verify exclusions are reasonable
- Does NOT check if there are conflicting policies
- Exclusions warning is shown but policy still passes

**Impact**: FALSE POSITIVE (could pass with excessive exclusions)

**Recommendation**: Consider failing if exclusions exceed a threshold (e.g., more than 5 users/groups excluded)

---

### MEDIUM PRIORITY

#### 4. Control 5.1.6.3 - Guest Inviter Role (L2)
**Issue**: Only checks for "adminsAndGuestInviters" value
**Current Check**: Fails if AllowInvitesFrom != "adminsAndGuestInviters"
**Problem**:
- "adminsGuestInvitersAndAllMembers" would FAIL
- "everyone" would FAIL (correct)
- "adminsOnly" would FAIL (but this is MORE restrictive than required!)
- CIS says "admins and guest inviters" but doesn't say "admins only" is non-compliant

**Impact**: FALSE NEGATIVE (fails when "adminsOnly" which is more secure)

**Recommendation**:
```powershell
# Should PASS for both:
if ($authPolicy.AllowInvitesFrom -eq "adminsAndGuestInviters" -or
    $authPolicy.AllowInvitesFrom -eq "adminsOnly") {
    # PASS - Properly restricted
}
```

---

#### 5. Control 2.1.14 - Anti-spam Allowed Domains
**Issue**: Checks AllowedSenderDomains and AllowedSenders
**Current Check**: Fails if ANY policy has allowed domains/senders
**Problem**:
- Some organizations may legitimately need to allow specific trusted senders
- CIS wording: "do not contain allowed domains" - but zero tolerance may be too strict
- Should perhaps warn instead of fail, or allow exceptions

**Impact**: FALSE POSITIVE (may fail for legitimate business requirements)

**Recommendation**: Consider making this a WARNING with details, or allow a small threshold

---

#### 6. Control 6.1.2 - Mailbox Audit Actions
**Issue**: Only samples 5 mailboxes
**Current Check**: Gets only 5 mailboxes to verify audit actions
**Problem**:
- Large tenants may have inconsistent settings
- 5 mailboxes is not statistically significant
- Could miss mailboxes with overridden settings

**Impact**: FALSE NEGATIVE (might miss non-compliant mailboxes)

**Recommendation**: Increase sample size to at least 50-100 mailboxes, or make it configurable

---

### LOW PRIORITY

#### 7. Control 5.2.2.4 - Admin Sign-in Frequency
**Issue**: Complex validation logic with multiple acceptable values
**Current Check**: Accepts hours ≤4, days=1, or "everyTime"
**Concern**:
- Multiple code paths to maintain
- Edge cases with different frequency types

**Impact**: Low - logic appears correct but complex

**Recommendation**: Add unit tests for this control

---

#### 8. Control 7.3.4 - Site Custom Scripts
**Issue**: Filters out specific site templates
**Current Check**: Excludes personal sites, redirect, app catalog, etc.
**Problem**:
- Template list may be incomplete
- New template types added by Microsoft won't be filtered
- False positives if DenyAddAndCustomizePages doesn't apply to new templates

**Impact**: FALSE POSITIVE (could fail for sites where setting doesn't apply)

**Recommendation**: Keep updated list of excluded templates, consider catching errors for templates where setting doesn't exist

---

## CONTROLS THAT APPEAR CORRECT

### Recently Fixed (v2.4.0 - v2.4.3)
- ✅ 5.2.3.1 - Microsoft Authenticator MFA fatigue (v2.4.3 - accepts "default" state, added location check)
- ✅ 5.1.3.1 - Dynamic guest group detection (v2.4.1)
- ✅ 5.2.2.4 - Admin sign-in frequency validation (v2.4.0)
- ✅ 5.2.2.10 - MFA registration managed device (v2.4.0)
- ✅ 5.2.2.11 - Intune enrollment frequency (v2.4.0)
- ✅ 5.2.3.2 - Custom banned passwords (v2.4.1)
- ✅ 5.2.3.6 - System-preferred MFA (v2.4.0)
- ✅ 5.2.4.1 - SSPR for all (v2.3.8 - marked as Manual)
- ✅ 6.1.2 - Mailbox audit actions (v2.3.9)
- ✅ 6.5.3 - OWA storage providers (v2.4.0)
- ✅ 7.2.3 - External content sharing (v2.3.8, enhanced v2.4.1)
- ✅ 7.2.4 - OneDrive sharing (v2.4.0)
- ✅ 7.3.3 - Custom scripts on personal sites (v2.3.9)
- ✅ 8.2.1 - Teams external domains (v2.4.0)
- ✅ 8.4.1 - Teams app policies (v2.4.0)

### Previously Verified Controls
- ✅ 5.1.6.2 - Guest user access restricted (GUID check)
- ✅ 5.2.2.12 - Device code flow blocking (v2.3.9)
- ✅ 5.2.3.5 - Weak auth methods disabled
- ✅ 5.2.3.4 - All users MFA capable
- ✅ 6.1.1 - Mailbox audit enabled
- ✅ 6.1.3 - Mailbox audit bypass
- ✅ 2.4.4 - ZAP for Teams (v2.3.9)

---

## RECOMMENDATIONS BY PRIORITY

### Immediate Action Required (Fix in v2.4.2)
1. **Fix 5.1.5.1** - User consent validation logic
2. **Fix 5.2.2.1** - Admin MFA role coverage validation
3. **Fix 5.1.6.3** - Allow "adminsOnly" as compliant

### Consider for Next Release (v2.5.0)
4. **Enhance 5.2.2.2** - Add exclusion threshold
5. **Enhance 6.1.2** - Increase mailbox sample size
6. **Review 2.1.14** - Consider warning vs fail for allowed domains

### Documentation/Testing
7. Add unit tests for complex validation logic
8. Document known limitations in README
9. Add parameter for mailbox sample size

---

## TESTING RECOMMENDATIONS

For each identified issue, test scenarios should include:

1. **5.1.5.1 User Consent**:
   - Empty PermissionGrantPoliciesAssigned array
   - Array with legacy policy
   - Array with custom policy
   - Array with multiple policies

2. **5.2.2.1 Admin MFA**:
   - Policy with single admin role
   - Policy with all directory roles
   - Policy with subset of admin roles
   - Multiple policies covering different roles

3. **5.1.6.3 Guest Inviter**:
   - adminsAndGuestInviters (should pass)
   - adminsOnly (should pass)
   - everyone (should fail)
   - adminsGuestInvitersAndAllMembers (should fail)

---

## CONCLUSION

**Overall Assessment**: The module has significantly improved accuracy with v2.4.0 and v2.4.1 releases. However, **3 HIGH PRIORITY** issues were identified that could result in false positives/negatives:

1. User consent validation (5.1.5.1) - FALSE NEGATIVE risk
2. Admin MFA role coverage (5.2.2.1) - FALSE POSITIVE risk
3. Guest inviter validation (5.1.6.3) - FALSE NEGATIVE risk

**Recommendation**: Create v2.4.2 to address these 3 high-priority issues before they cause user confusion.
