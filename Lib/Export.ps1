<#
.SYNOPSIS
    Winflesher - Attack Surface Security Framework by mindsflee (Alessandro Salzano)
.DESCRIPTION
    Winflesher is an advanced attack surface security assessment framework designed 
    to analyze, evaluate, and report on security postures, attack paths, and 
    remediation strategies.
.COMPONENT
    Internal Utility / Export Module
#>

function Export-WFLReportHtml {
    [CmdletBinding()]
    param(
        [string]$Folder = ".\Reports"
    )

    Write-Verbose "Starting HTML report generation..."

    try {
        if (-not (Test-Path -Path $Folder)) {
            Write-Verbose "Target folder '$Folder' does not exist. Creating directory..."
            $null = New-Item -Path $Folder -ItemType Directory -Force -ErrorAction Stop
        }
        $Folder = (Resolve-Path -Path $Folder).Path
        Write-Verbose "Target directory resolved to: $Folder"
    } catch {
        Write-Error "Unable to create or access target directory: $_"
        return
    }

    $Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Path = Join-Path $Folder "WinFlesher-Report-$Stamp.html"

    $LogoPath = ".\Assets\Logo\winflesher_logo.png"
    $HeaderContent = ""
    if (Test-Path $LogoPath) {
        try {
            $ImageBytes = [System.IO.File]::ReadAllBytes($LogoPath)
            $Base64Str = [System.Convert]::ToBase64String($ImageBytes)
            $HeaderContent = "<img src='data:image/jpeg;base64,$Base64Str' alt='WinFlesher Logo' class='header-logo'>"
            Write-Verbose "Logo loaded and converted to embedded Base64 successfully."
        }
        catch {
            Write-Verbose "Failed to load logo from '$LogoPath': $_. Falling back to text title."
            $HeaderContent = "<h1>WinFlesher Security Assessment</h1>"
        }
    } else {
        Write-Verbose "Logo file not found at '$LogoPath'. Falling back to text title."
        $HeaderContent = "<h1>WinFlesher Security Assessment</h1>"
    }

    Write-Verbose "Gathering score, summary, and findings data..."
    $Score = Get-WFLScore
    $Summary = @(Get-WFLSummaryByCategory)
    
    $SeverityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4; "Info" = 5 }
    $Findings = @($Global:WinFlesher.Findings | Sort-Object { 
        if ($SeverityOrder.ContainsKey($_.Severity)) { $SeverityOrder[$_.Severity] } else { 99 }
    }, Category, Title)

    $Modules = @(Get-WFLModules)

    $DetailsIndex = foreach ($Key in ($Global:WinFlesher.Details.Keys | Sort-Object)) {
        [PSCustomObject]@{
            DetailName = $Key
            Count      = @($Global:WinFlesher.Details[$Key]).Count
        }
    }

    Write-Verbose "Converting data fragments to HTML..."
    $SummaryHtml  = $Summary | ConvertTo-Html -Fragment
    
    $FindingsRows = foreach ($f in $Findings) {
        $sevClass = "sev-$($f.Severity.ToLower())"
        "<tr><td>$($f.Time)</td><td class='$sevClass'><b>$($f.Severity)</b></td><td>$($f.Category)</td><td>$($f.MITRE)</td><td>$($f.Tactic)</td><td>$($f.Impact)</td><td>$($f.Title)</td><td>$($f.Evidence)</td><td>$($f.Recommendation)</td><td>$($f.Source)</td></tr>"
    }
    $FindingsHtml = "<table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>MITRE</th><th>Tactic</th><th>Impact</th><th>Title</th><th>Evidence</th><th>Recommendation</th><th>Source</th></tr></thead><tbody>" + ($FindingsRows -join "`n") + "</tbody></table>"

    $ModulesHtml  = $Modules | ConvertTo-Html -Fragment
    
   
    $DetailsFullHtml = "<div class='details-grid'>"
    foreach ($Key in ($Global:WinFlesher.Details.Keys | Sort-Object)) {
        $Items = @($Global:WinFlesher.Details[$Key])
        if ($Items.Count -eq 0) { continue } 

        $visibleItems = $Items | Select-Object -First 3
        $hiddenItems  = $Items | Select-Object -Skip 3

        $DetailsFullHtml += @"
        <div class='card detail-card'>
            <h3>$Key</h3>
            <ul class='detail-list'>
"@
        foreach ($Item in $visibleItems) {
            $content = if ($Item -is [string]) { $Item } else { ($Item | Out-String).Trim() }
            $DetailsFullHtml += "<li>$($content -replace '\n','<br>')</li>"
        }
        $DetailsFullHtml += "</ul>"

        if ($hiddenItems.Count -gt 0) {
            $DetailsFullHtml += "<details class='detail-more-container'><summary class='more-btn'>More ($($hiddenItems.Count) items)...</summary><ul class='detail-list' style='margin-top: 8px;'>"
            foreach ($Item in $hiddenItems) {
                $content = if ($Item -is [string]) { $Item } else { ($Item | Out-String).Trim() }
                $DetailsFullHtml += "<li>$($content -replace '\n','<br>')</li>"
            }
            $DetailsFullHtml += "</ul></details>"
        }

        $DetailsFullHtml += "</div>"
    }
    $DetailsFullHtml += "</div>"
  

    Write-Verbose "Generating Remediation and Attack Path sections..."
    
    $RemediationData = Get-FilteredRemediationReport -Findings $Global:WinFlesher.Findings
    $RemediationHtml = foreach ($item in $RemediationData) {
        @"
        <div class='card' style='margin-bottom: 20px;'>
            <h3 style='color: var(--info-color); margin-top: 0;'>[$($item.Severity)] $($item.Module)</h3>
            <pre style='background: #0f172a; padding: 15px; border-radius: 8px; font-size: 13px; color: #cbd5e1; overflow-x: auto; margin: 0;'>$($item.FormattedBlock)</pre>
        </div>
"@
    }

    $rawAttackPathOutput = & {
        Show-AttackPaths 6>&1 2>&1 | Out-String
    }

    if ([string]::IsNullOrWhiteSpace($rawAttackPathOutput)) {
        $writer = New-Object System.IO.StringWriter
        $oldOut = [Console]::Out
        [Console]::SetOut($writer)
        try {
            Show-AttackPaths
        }
        finally {
            [Console]::SetOut($oldOut)
        }
        $rawAttackPathOutput = $writer.ToString()
    }

    $encodedAttackPath = [System.Net.WebUtility]::HtmlEncode($rawAttackPathOutput)
    $AttackPathHtml = "<div class='card'><pre style='background: #0f172a; padding: 15px; color: #f8fafc; font-size: 13px; overflow-x: auto; margin: 0;'>$encodedAttackPath</pre></div>"

    $ComputerName = ""
    $Domain = ""
    $OS = ""

    try {
        $ComputerName = $Global:WinFlesher.Context.Host.ComputerName
        $Domain = $Global:WinFlesher.Context.Host.Domain
        $OS = $Global:WinFlesher.Context.Host.OS
    }
    catch {
        Write-Verbose "Could not retrieve target host context metadata."
    }

    $HealthVal = [math]::Max(0, [math]::Min(100, [double]$Score.Score))

    if ($HealthVal -le 20)      { $ScoreColor = "#ef4444" }
    elseif ($HealthVal -le 40) { $ScoreColor = "#f97316" }
    elseif ($HealthVal -le 60) { $ScoreColor = "#eab308" }
    elseif ($HealthVal -le 80) { $ScoreColor = "#3b82f6" }
    else                       { $ScoreColor = "#10b981" }

    Write-Verbose "Calculating offline SVG donut chart segments..."
    $ScorePct = "{0:0.####}" -f $HealthVal
    $RestPct  = "{0:0.####}" -f (100 - $HealthVal)
    
    $SvgChart = @"
<svg viewBox="0 0 36 36" class="donut-svg" style="transform: rotate(-90deg);">
    <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#334155" stroke-width="3.8"/>
    <circle cx="18" cy="18" r="15.915" fill="transparent" 
            stroke="$ScoreColor" stroke-width="3.8" 
            stroke-dasharray="$ScorePct $RestPct" 
            stroke-dashoffset="0" 
            stroke-linecap="round"/>
</svg>
"@

    Write-Verbose "Assembling final HTML template..."
    $Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WinFlesher Executive Security Report</title>
<style>
:root {
    --bg-main: #0f172a;
    --card-bg: #1e293b;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --border-color: #334155;
    --critical-color: #c084fc;
    --high-color: #ef4444;
    --medium-color: #f97316;
    --low-color: #eab308;
    --info-color: #38bdf8;
}

body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background-color: var(--bg-main) !important;
    color: var(--text-primary) !important;
    margin: 0;
    padding: 32px;
}

.header-container {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2px solid var(--border-color);
    padding-bottom: 16px;
    margin-bottom: 28px;
}

.header-logo {
    max-height: 150px;
    width: auto;
    display: block;
}

h1 {
    margin: 0;
    font-size: 28px;
    color: #38bdf8;
    letter-spacing: -0.5px;
}

h2 {
    margin-top: 36px;
    font-size: 20px;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 8px;
}

.dashboard-grid {
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: 24px;
    margin-bottom: 28px;
}

.card {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
}

.chart-container {
    position: relative;
    width: 220px;
    height: 220px;
    margin: 0 auto;
}

.donut-svg {
    width: 100%;
    height: 100%;
}

.chart-center-text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}

.chart-center-score {
    font-size: 44px;
    font-weight: 800;
    line-height: 1;
    color: $ScoreColor;
}

.chart-center-label {
    font-size: 11px;
    text-transform: uppercase;
    color: var(--text-secondary);
    margin-top: 4px;
    letter-spacing: 1px;
}

.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 16px;
}

.meta-item {
    background: #0f172a;
    padding: 12px 16px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.meta-item .label {
    font-size: 11px;
    text-transform: uppercase;
    color: var(--text-secondary);
    display: block;
    margin-bottom: 4px;
}

.meta-item .val {
    font-size: 15px;
    font-weight: 600;
}

.badge-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 16px;
}

.badge {
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
}

.badge-critical { background: rgba(192, 132, 252, 0.15); color: var(--critical-color); border: 1px solid var(--critical-color); }
.badge-high     { background: rgba(239, 68, 68, 0.15); color: var(--high-color); border: 1px solid var(--high-color); }
.badge-medium   { background: rgba(249, 115, 22, 0.15); color: var(--medium-color); border: 1px solid var(--medium-color); }
.badge-low      { background: rgba(234, 179, 8, 0.15);  color: var(--low-color); border: 1px solid var(--low-color); }
.badge-info     { background: rgba(56, 189, 248, 0.15); color: var(--info-color); border: 1px solid var(--info-color); }

td.sev-critical { color: var(--critical-color) !important; }
td.sev-high     { color: var(--high-color) !important; }
td.sev-medium   { color: var(--medium-color) !important; }
td.sev-low      { color: var(--low-color) !important; }
td.sev-info     { color: var(--info-color) !important; }

table {
    border-collapse: collapse !important;
    width: 100% !important;
    background: var(--card-bg) !important;
    border-radius: 8px !important;
    overflow: hidden !important;
    margin-top: 12px !important;
    border: 1px solid var(--border-color) !important;
}

th {
    background: #0f172a !important;
    color: #38bdf8 !important;
    padding: 12px !important;
    text-align: left !important;
    font-size: 13px !important;
    border-bottom: 1px solid var(--border-color) !important;
}

tr {
    background-color: transparent !important;
}

td {
    border-bottom: 1px solid var(--border-color) !important;
    padding: 10px 12px !important;
    vertical-align: top !important;
    font-size: 13px !important;
    color: #cbd5e1 !important;
    background-color: transparent !important;
}

tr:hover {
    background: #334155 !important;
}

.footer {
    color: var(--text-secondary);
    font-size: 12px;
    margin-top: 40px;
    text-align: center;
    border-top: 1px solid var(--border-color);
    padding-top: 16px;
}

.details-grid {
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    display: grid;
    gap: 16px;
    margin-top: 20px;
}

.detail-card {
    padding: 16px;
    word-break: break-word;
    overflow-wrap: break-word;
}

.detail-card h3 {
    margin: 0 0 10px 0;
    font-size: 16px;
    color: #38bdf8;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 8px;
}

.detail-list {
    margin: 0;
    padding-left: 18px;
    font-size: 12px;
    color: #cbd5e1;
    list-style-type: square;
}

.detail-card li {
    margin-bottom: 6px;
    word-break: break-word;
}

details.detail-more-container {
    margin-top: 10px;
}

summary.more-btn {
    display: inline-block;
    color: #38bdf8;
    background: rgba(56, 189, 248, 0.1);
    border: 1px solid rgba(56, 189, 248, 0.3);
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
    border-radius: 6px;
    cursor: pointer;
    outline: none;
    user-select: none;
    transition: background 0.2s;
}

summary.more-btn:hover {
    background: rgba(56, 189, 248, 0.2);
}

details[open] summary.more-btn {
    margin-bottom: 8px;
}

pre {
    white-space: pre-wrap;        
    word-wrap: break-word;
    font-family: 'Consolas', 'Monaco', monospace;
}
</style>
</head>
<body>

<div class="header-container">
    $HeaderContent
    <div style="font-size: 13px; color: var(--text-secondary);">
        Engine Version: <b>$($Global:WinFlesher.Version)</b>
    </div>
</div>

<div class="dashboard-grid">
    <div class="card" style="display: flex; flex-direction: column; align-items: center; justify-content: center;">
        <div class="chart-container">
            $SvgChart
            <div class="chart-center-text">
                <div class="chart-center-score">$HealthVal</div>
                <div class="chart-center-label">Health Score</div>
            </div>
        </div>
    </div>

    <div class="card" style="display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            <h3 style="margin-top: 0; margin-bottom: 16px; color: var(--text-primary);">Assessment Environment</h3>
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="label">Computer</span>
                    <span class="val">$ComputerName</span>
                </div>
                <div class="meta-item">
                    <span class="label">Domain</span>
                    <span class="val">$Domain</span>
                </div>
                <div class="meta-item">
                    <span class="label">Operating System</span>
                    <span class="val">$OS</span>
                </div>
                <div class="meta-item">
                    <span class="label">Generated At</span>
                    <span class="val">$((Get-Date).ToString("yyyy-MM-dd HH:mm"))</span>
                </div>
            </div>
        </div>

        <div>
            <span class="label" style="font-size: 11px; text-transform: uppercase; color: var(--text-secondary);">Findings Overview (Rating: $($Score.Rating))</span>
            <div class="badge-list">
                <span class="badge badge-critical">Critical: $($Score.Critical)</span>
                <span class="badge badge-high">High: $($Score.High)</span>
                <span class="badge badge-medium">Medium: $($Score.Medium)</span>
                <span class="badge badge-low">Low: $($Score.Low)</span>
                <span class="badge badge-info">Info: $($Score.Info)</span>
            </div>
        </div>
    </div>
</div>

<h2>Summary by Category</h2>
$SummaryHtml

<h2>Findings Overview</h2>
$FindingsHtml

<h2>Module Technical Details</h2>
$DetailsFullHtml

<h2>Module Remediation Details</h2>
<div id="remediation-section">
    $RemediationHtml
</div>

<h2>Attack Path Analysis</h2>
<div id="attack-path-section">
    $AttackPathHtml
</div>

<h2>Loaded Assessment Modules</h2>
$ModulesHtml

<div class="footer">
    Generated by WinFlesher Attack Surface Security Framefork v$($Global:WinFlesher.Version) by 'mindsflee' (Alessandro Salzano) 
</div>

</body>
</html>
"@

    Write-Verbose "Writing report to disk at: $Path"
    Set-Content -Path $Path -Value $Html -Encoding UTF8

    Write-Verbose "HTML report generated successfully."
    return $Path
}