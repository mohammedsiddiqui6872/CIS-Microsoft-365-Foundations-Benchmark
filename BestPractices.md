# CIS-M365-Benchmark Module - Best Practices & Code Audit Findings

> Generated from comprehensive code audit on 2026-02-24
> Module Version: 3.0.5 | CIS Benchmark: v6.0.0

---

## Table of Contents

1. [Critical Bugs](#critical-bugs)
2. [High Severity Issues](#high-severity-issues)
3. [Medium Severity Issues](#medium-severity-issues)
4. [Low Severity Issues](#low-severity-issues)
5. [Best Practices Applied](#best-practices-applied)

---

## Critical Bugs

### 1. Intune Checks Produce False Passes (Controls 4.1 & 4.2)

**File:** `CIS-M365-Compliance-Checker.ps1` lines 1011-1019

**Problem:** Control 4.1 checks if `intuneAccountId` exists instead of verifying the actual compliance policy default behavior. Control 4.2 checks if restriction policies exist rather than verifying personal devices are blocked.

**Best Practice:** Always verify the *actual setting value* against the CIS benchmark requirement, not just the existence of a configuration object.

### 2. HTML Report XSS Vulnerability

**File:** `CIS-M365-Compliance-Checker.ps1` lines 3752-3760

**Problem:** User-controlled data (tenant names, group names, policy names) interpolated directly into HTML without encoding. Malicious object names containing `<script>` tags will execute in the browser.

**Best Practice:** Always HTML-encode any dynamic data before inserting into HTML output. Use `[System.Net.WebUtility]::HtmlEncode()` for all interpolated values in report generation.

### 3. Password Expiration False Pass (Control 1.3.1)

**File:** `CIS-M365-Compliance-Checker.ps1` line 362

**Problem:** The check passes if `PasswordValidityPeriodInDays > 365`, but CIS requires the value to be exactly `2147483647` (never expire). A 400-day policy incorrectly passes.

**Best Practice:** Match the exact CIS benchmark requirement. "Never expire" means `2147483647`, not "a long time."

### 4. Array Property Access on Collections (Control 6.2.1)

**File:** `CIS-M365-Compliance-Checker.ps1` lines 2375-2384

**Problem:** `Get-HostedOutboundSpamFilterPolicy` returns multiple policies. Accessing `.AutoForwardingMode` on an array produces an array of values, causing unreliable comparison.

**Best Practice:** Always iterate collections explicitly. Never access properties directly on a cmdlet result that may return multiple objects.

### 5. Incomplete Public API (Get-CISBenchmarkControl)

**File:** `CIS-M365-Benchmark.psm1` lines 589-593

**Problem:** Only 3 of 140 controls are hardcoded. The exported function returns empty results for most queries.

**Best Practice:** If you export a public function, it must work completely. Either populate all data or clearly document limitations.

---

## High Severity Issues

### 6. O(n^2) Array Growth Pattern

**File:** `CIS-M365-Compliance-Checker.ps1` line 143

**Problem:** `$Script:Results += [PSCustomObject]@{...}` copies the entire array on every append.

**Best Practice:** Use `[System.Collections.Generic.List[PSCustomObject]]` for collections that grow incrementally. Call `.Add()` instead of `+=`.

### 7. Null Reference on Missing Scopes

**File:** `CIS-M365-Benchmark.psm1` line 242

**Problem:** `$currentContext.Scopes` may be `$null`, causing `-notin $null` to report all scopes as missing.

**Best Practice:** Always null-check properties before using them in comparisons. Guard with `if ($null -ne $currentContext.Scopes)`.

### 8. Null Check Order Inversion

**File:** `CIS-M365-Compliance-Checker.ps1` line 2349

**Problem:** `.Count` is accessed before null check. PowerShell's loose typing makes this accidentally work, but it's fragile.

**Best Practice:** Always check `$null` before accessing properties: `if ($null -eq $var -or $var.Count -eq 0)`.

### 9. `.Count` Fails on Single Objects in PowerShell 5.1

**File:** `CIS-M365-Compliance-Checker.ps1` lines 810-811

**Problem:** In PS 5.1, single objects don't have `.Count`. A policy with one allowed domain returns `$null` for `.Count`.

**Best Practice:** Always wrap in `@()` to force array context: `@($collection).Count`.

### 10. Empty Catch Block Swallows Errors

**File:** `CIS-M365-Benchmark.psm1` lines 199-200

**Problem:** Outer catch block in `Fix-MicrosoftGraphVersion` is completely empty, silently swallowing all errors.

**Best Practice:** Never use empty catch blocks. At minimum, log the error with `Write-Verbose` or `Write-Warning`.

### 11. Module Auto-Installs Dependencies on Import

**File:** `CIS-M365-Benchmark.psm1` lines 204-207

**Problem:** `Import-Module` triggers automatic installation of 4 modules without user consent. Breaks corporate environments with restricted PSGallery access.

**Best Practice:** Never perform side effects on module import. Defer dependency checks to the first function invocation, and always prompt the user before installing anything.

---

## Medium Severity Issues

### 12. Supply Chain Risk with -Force -AllowClobber

**File:** `CIS-M365-Benchmark.psm1` lines 66, 83, 109, 177

**Problem:** `-AllowClobber` overwrites existing commands without warning. `-Force` bypasses publisher trust. No version pinning.

**Best Practice:** Remove `-AllowClobber`. Use `-Force` only when necessary. Pin module versions to tested ranges.

### 13. Environment Variable Leaks Auth State

**File:** `CIS-M365-Benchmark.psm1` lines 263, 347

**Problem:** `$env:CIS_USE_DEVICE_CODE = "true"` persists for the entire process and is never cleaned up.

**Best Practice:** Clean up environment variables after use. Use script-scoped variables instead of environment variables for internal state.

### 14. Script-Scope Variables Prevent Concurrent Use

**File:** `CIS-M365-Compliance-Checker.ps1` lines 53-70

**Problem:** All results stored in `$Script:` variables. Concurrent runs corrupt each other's data.

**Best Practice:** Reset all script-scope variables at the start of each run. Consider returning results from functions instead.

### 15. Hardcoded Application Client ID

**File:** `CIS-M365-Benchmark.psm1` line 300

**Problem:** Microsoft Graph SDK's well-known client ID is hardcoded without documentation.

**Best Practice:** Use default SDK authentication. If custom IDs are needed, document why and make them configurable.

### 16. Excessive `-ErrorAction SilentlyContinue` Masks Failures

**Problem:** 50+ uses across both files. Critical API calls that fail silently cause downstream checks to produce false positives.

**Best Practice:** Use `-ErrorAction Stop` with `try/catch` for critical operations. Reserve `SilentlyContinue` only for genuinely optional checks where failure is expected and handled.

### 17. Backup File in Repository

**File:** `CIS-M365-Benchmark.psm1.bak`

**Best Practice:** Never commit backup files. Add `*.bak` to `.gitignore` and remove tracked backup files.

---

## Low Severity Issues

### 18. Pointless try/catch on Manual Controls

**Problem:** Static `Add-Result -Result "Manual"` calls wrapped in try/catch. These cannot throw.

**Best Practice:** Only use try/catch around code that can actually throw exceptions.

### 19. Duplicate API Calls

**Problem:** `Get-AcceptedDomain` called twice independently for SPF and DMARC checks.

**Best Practice:** Pre-fetch shared data once and pass it to dependent checks, like the existing `$cachedMalwareFilterPolicy` pattern.

### 20. No File-Based Logging

**Problem:** `Write-Log` only outputs to console. No audit trail for compliance checks.

**Best Practice:** For compliance tools, always write logs to a file with timestamps, check names, results, and errors. This provides evidence for auditors and helps debug issues.

### 21. Inconsistent Boolean Comparisons

**Problem:** Mix of `-eq $true`, `-eq $false`, and truthy checks throughout the codebase.

**Best Practice:** Pick one style and be consistent. Explicit `-eq $true` / `-eq $false` is clearer for compliance checks where the distinction between `$null`, `$false`, and `$true` matters.

### 22. Missing `#Requires` Statement

**File:** `CIS-M365-Compliance-Checker.ps1`

**Problem:** No `#Requires -Version 5.1` in the main checker script.

**Best Practice:** Always include `#Requires` statements so PowerShell provides clear error messages instead of cryptic failures.

### 23. ValidatePattern Too Strict for Government Clouds

**File:** `CIS-M365-Benchmark.psm1` line 385

**Problem:** Only accepts `.sharepoint.com` URLs. Rejects GCC High (`.sharepoint.us`), DoD, Germany (`.sharepoint.de`), and China (`.sharepoint.cn`) sovereign clouds.

**Best Practice:** Support all Microsoft sovereign cloud domains in URL validation patterns.

---

## Best Practices Applied

After this audit, the following best practices have been implemented:

1. **Validate the actual setting, not just existence** - Intune checks now verify specific compliance policy values
2. **HTML-encode all dynamic output** - XSS prevention via `[System.Net.WebUtility]::HtmlEncode()`
3. **Match exact CIS requirements** - No approximations on compliance thresholds
4. **Iterate collections explicitly** - Never assume cmdlets return single objects
5. **Use efficient collection types** - `List<T>` instead of array `+=` for growing collections
6. **Null-safe property access** - Always check for `$null` before accessing properties
7. **Force array context** - `@($collection).Count` for PS 5.1 compatibility
8. **Never use empty catch blocks** - Always log or handle errors meaningfully
9. **No side effects on module import** - Defer dependency installation to explicit user action
10. **Clean up environment state** - Remove env vars after use, reset script variables between runs
11. **Proper error handling** - Use `-ErrorAction Stop` with try/catch for critical operations
12. **Support sovereign clouds** - Accept all Microsoft cloud domain patterns
13. **File-based audit logging** - Persistent log files for compliance evidence
14. **Complete public APIs** - Exported functions must return correct, complete data
