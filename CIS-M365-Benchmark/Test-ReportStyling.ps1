# Quick test script to preview the new CIS report styling
# This generates a sample report without running actual compliance checks

$currentTenantId = "12345678-1234-1234-1234-123456789abc"
$currentUserAccount = "admin@contoso.onmicrosoft.com"
$reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"

# Mock some sample results
$Script:TotalControls = 150
$Script:PassedControls = 95
$Script:FailedControls = 35
$Script:ManualControls = 15
$Script:ErrorControls = 5

$passRate = [math]::Round(($Script:PassedControls / ($Script:TotalControls - $Script:ManualControls)) * 100, 2)

# Create sample results array
$Script:Results = @(
    [PSCustomObject]@{
        ControlNumber = "1.1.1"
        ControlTitle = "Ensure Administrative accounts are cloud-only"
        ProfileLevel = "L1"
        Result = "Pass"
        Details = "All administrative accounts are cloud-only accounts."
        Remediation = ""
    }
    [PSCustomObject]@{
        ControlNumber = "2.1.1"
        ControlTitle = "Ensure Safe Links for Office Applications is Enabled"
        ProfileLevel = "L1"
        Result = "Fail"
        Details = "Safe Links is not enabled for Office applications."
        Remediation = "Enable Safe Links in Microsoft 365 Defender portal."
    }
    [PSCustomObject]@{
        ControlNumber = "3.1.1"
        ControlTitle = "Ensure Microsoft 365 audit log search is Enabled"
        ProfileLevel = "L1"
        Result = "Pass"
        Details = "Audit log search is enabled."
        Remediation = ""
    }
    [PSCustomObject]@{
        ControlNumber = "5.1.2.1"
        ControlTitle = "Ensure 'Per-user MFA' is disabled"
        ProfileLevel = "L1"
        Result = "Manual"
        Details = "This check requires manual verification."
        Remediation = ""
    }
    [PSCustomObject]@{
        ControlNumber = "6.1.1"
        ControlTitle = "Ensure modern authentication for Exchange Online is enabled"
        ProfileLevel = "L1"
        Result = "Pass"
        Details = "Modern authentication is enabled."
        Remediation = ""
    }
    [PSCustomObject]@{
        ControlNumber = "7.1.1"
        ControlTitle = "Ensure external content sharing is restricted"
        ProfileLevel = "L2"
        Result = "Fail"
        Details = "External sharing is set to 'Anyone'."
        Remediation = "Restrict external sharing to 'Existing guests' or more restrictive."
    }
)

$reportPath = "CIS-M365-Compliance-Report_PREVIEW_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Microsoft 365 Compliance Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0a0a0c; color: #e4e4e7; }
        .container { max-width: 1400px; margin: 0 auto; }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 3px solid #60a5fa;
        }
        .header h1 {
            font-size: 1.8em;
            font-weight: 700;
            letter-spacing: -1px;
            margin: 0;
            color: white;
        }
        .subtitle {
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 4px;
            color: white;
        }
        .header-right {
            text-align: right;
            font-size: 0.85em;
            color: white;
        }
        .header-right > div {
            margin-bottom: 2px;
        }

        /* Content */
        .content { padding: 20px 40px; }
        h2 { color: #60a5fa; margin-top: 30px; margin-bottom: 15px; }

        .summary { background: #18181b; padding: 20px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #27272a; }
        .summary-box {
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 15px 25px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .summary-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
        }
        .summary-box.active {
            box-shadow: 0 0 15px rgba(96, 165, 250, 0.4);
            border: 2px solid #60a5fa !important;
        }
        .pass { background-color: #14532d; color: #4ade80; border: 1px solid #166534; }
        .fail { background-color: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
        .manual { background-color: #422006; color: #fbbf24; border: 1px solid #78350f; }
        .error { background-color: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }

        .progress-bar { width: 100%; height: 30px; background-color: #27272a; border-radius: 5px; overflow: hidden; margin: 15px 0; }
        .progress-fill { height: 100%; background-color: #22c55e; text-align: center; line-height: 30px; color: white; font-weight: bold; }

        table { width: 100%; border-collapse: collapse; background: #18181b; border: 1px solid #27272a; margin-top: 20px; }
        th { background-color: #1e3a8a; color: white; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #60a5fa; }
        td { padding: 12px; border-bottom: 1px solid #27272a; }
        tr:hover { background-color: #27272a; }
        .status-pass { color: #4ade80; font-weight: bold; }
        .status-fail { color: #f87171; font-weight: bold; }
        .status-manual { color: #fbbf24; font-weight: bold; }
        .status-error { color: #f87171; font-weight: bold; }
        .details { font-size: 0.9em; color: #a1a1aa; }
        .remediation { font-size: 0.85em; color: #60a5fa; font-style: italic; margin-top: 5px; }

        /* Floating Action Buttons (Right Side) */
        .floating-actions {
            position: fixed;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            display: flex;
            flex-direction: column;
            gap: 12px;
            z-index: 1000;
        }
        .action-btn {
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            border: 2px solid #60a5fa;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            font-size: 20px;
            font-weight: bold;
            color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            position: relative;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .action-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 8px 20px rgba(96, 165, 250, 0.4);
            border-color: #93c5fd;
        }
        .action-btn::before {
            content: attr(data-tooltip);
            position: absolute;
            right: 70px;
            background: #18181b;
            color: #e4e4e7;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
            border: 1px solid #3f3f46;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .action-btn:hover::before {
            opacity: 1;
        }

        /* Footer */
        .footer {
            background: #18181b;
            color: #a1a1aa;
            padding: 15px 40px;
            text-align: center;
            border-top: 1px solid #27272a;
            margin-top: 40px;
            font-size: 0.9em;
        }
        .footer p { margin: 0; }
        .footer a { color: #60a5fa; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }

        /* Hidden class for filtering */
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <h1>CIS MICROSOFT 365 FOUNDATIONS BENCHMARK v5.0.0</h1>
                <div class="subtitle">Microsoft 365 Tenant</div>
                <div class="subtitle" style="font-size: 0.75em; margin-top: 4px; opacity: 0.8;">Tenant ID: $currentTenantId</div>
            </div>
            <div class="header-right">
                <div>Generated: $reportDate</div>
                <div>Run by: $currentUserAccount</div>
                <div>Total Controls: $Script:TotalControls</div>
                <div>Compliance Rate: $passRate%</div>
            </div>
        </div>

        <!-- Content -->
        <div class="content">

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="progress-bar">
            <div class="progress-fill" style="width: $passRate%">$passRate% Compliant</div>
        </div>
        <br/>
        <div class="summary-box pass" data-filter="pass" onclick="filterResults(this)">
            <strong>Passed:</strong> $Script:PassedControls
        </div>
        <div class="summary-box fail" data-filter="fail" onclick="filterResults(this)">
            <strong>Failed:</strong> $Script:FailedControls
        </div>
        <div class="summary-box manual" data-filter="manual" onclick="filterResults(this)">
            <strong>Manual:</strong> $Script:ManualControls
        </div>
        <div class="summary-box error" data-filter="error" onclick="filterResults(this)">
            <strong>Errors:</strong> $Script:ErrorControls
        </div>
        <div class="summary-box" data-filter="all" onclick="filterResults(this)">
            <strong>Total Controls:</strong> $Script:TotalControls
        </div>
    </div>

    <h2>Detailed Results (Sample Data)</h2>
    <table>
        <thead>
            <tr>
                <th>Control</th>
                <th>Title</th>
                <th>Level</th>
                <th>Result</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
"@

foreach ($result in $Script:Results | Sort-Object ControlNumber) {
    $statusClass = "status-" + $result.Result.ToLower()
    $resultLower = $result.Result.ToLower()
    $html += @"
            <tr data-result="$resultLower">
                <td><strong>$($result.ControlNumber)</strong></td>
                <td>$($result.ControlTitle)</td>
                <td>$($result.ProfileLevel)</td>
                <td class="$statusClass">$($result.Result)</td>
                <td>
                    <div class="details">$($result.Details)</div>
"@
    if ($result.Remediation -and $result.Result -eq "Fail") {
        $html += "                    <div class='remediation'>Remediation: $($result.Remediation)</div>`n"
    }
    $html += "                </td>`n            </tr>`n"
}

$html += @"
        </tbody>
    </table>
        </div>

        <!-- Floating Action Buttons -->
        <div class="floating-actions">
            <a href="https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0" target="_blank" class="action-btn" data-tooltip="View on GitHub">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
            </a>
            <a href="https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues" target="_blank" class="action-btn" data-tooltip="Report Issues">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 2c5.514 0 10 4.486 10 10s-4.486 10-10 10-10-4.486-10-10 4.486-10 10-10zm0-2c-6.627 0-12 5.373-12 12s5.373 12 12 12 12-5.373 12-12-5.373-12-12-12zm-1 6h2v8h-2v-8zm1 12.25c-.69 0-1.25-.56-1.25-1.25s.56-1.25 1.25-1.25 1.25.56 1.25 1.25-.56 1.25-1.25 1.25z"/></svg>
            </a>
            <a href="https://github.com/mohammedsiddiqui6872/CIS-Microsoft-365-Foundations-Benchmark-v5.0.0/issues/new" target="_blank" class="action-btn" data-tooltip="Submit Feedback">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 3c5.514 0 10 3.592 10 8.007 0 4.917-5.145 7.961-9.91 7.961-1.937 0-3.383-.397-4.394-.644-1 .613-1.595 1.037-4.272 1.82.535-1.373.723-2.748.602-4.265-.838-1-2.025-2.4-2.025-4.872-.001-4.415 4.485-8.007 9.999-8.007zm0-2c-6.338 0-12 4.226-12 10.007 0 2.05.739 4.063 2.047 5.625.055 1.83-1.023 4.456-1.993 6.368 2.602-.47 6.301-1.508 7.978-2.536 1.418.345 2.775.503 4.059.503 7.084 0 11.91-4.837 11.91-9.961-.001-5.811-5.702-10.006-12.001-10.006z"/></svg>
            </a>
            <a href="https://www.linkedin.com/in/mohammedsiddiqui6872/" target="_blank" class="action-btn" data-tooltip="Let's Chat!">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
            </a>
            <a href="https://buymeacoffee.com/mohammedsiddiqui" target="_blank" class="action-btn" data-tooltip="Buy Me a Coffee">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M20 3H4v10c0 2.21 1.79 4 4 4h6c2.21 0 4-1.79 4-4v-3h2c1.11 0 2-.9 2-2V5c0-1.11-.89-2-2-2zm0 5h-2V5h2v3zM4 19h16v2H4z"/></svg>
            </a>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>CIS Microsoft 365 Foundations Benchmark v5.0.0</strong> | Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | $Script:TotalControls controls | Run by: $currentUserAccount</p>
        </div>
    </div>

    <script>
        let activeFilter = null;

        function filterResults(box) {
            const filterValue = box.getAttribute('data-filter');
            const allRows = document.querySelectorAll('tbody tr');
            const allBoxes = document.querySelectorAll('.summary-box');

            // Toggle filter - if same box clicked, clear filter
            if (activeFilter === filterValue) {
                // Clear filter - show all
                allRows.forEach(row => row.classList.remove('hidden'));
                allBoxes.forEach(b => b.classList.remove('active'));
                activeFilter = null;
            } else {
                // Apply new filter
                activeFilter = filterValue;
                allBoxes.forEach(b => b.classList.remove('active'));
                box.classList.add('active');

                if (filterValue === 'all') {
                    // Show all rows
                    allRows.forEach(row => row.classList.remove('hidden'));
                } else {
                    // Filter by result type
                    allRows.forEach(row => {
                        const rowResult = row.getAttribute('data-result');
                        if (rowResult === filterValue) {
                            row.classList.remove('hidden');
                        } else {
                            row.classList.add('hidden');
                        }
                    });
                }
            }
        }
    </script>
</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  PREVIEW REPORT GENERATED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Report saved to: " -NoNewline
Write-Host $reportPath -ForegroundColor Cyan
Write-Host ""
Write-Host "Open this file in your browser to preview the new styling:" -ForegroundColor Yellow
Write-Host "  - Compact header with tenant ID and user info" -ForegroundColor Gray
Write-Host "  - Dark theme matching Secure Score reports" -ForegroundColor Gray
Write-Host "  - Footer with GitHub links and Buy Me a Coffee" -ForegroundColor Gray
Write-Host ""
Write-Host "Opening report in default browser..." -ForegroundColor Yellow
Start-Process $reportPath
