<#
.SYNOPSIS
    Winflesher - Attack Surface Security Framework by mindsflee (Alessandro Salzano)
.DESCRIPTION
    Winflesher is an advanced attack surface security assessment framework designed 
    to analyze, evaluate, and report on security postures, attack paths, and 
    remediation strategies.
.COMPONENT
    Remediation Engine Module - [remediation.ps1]
#>

function Get-FilteredRemediationReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Findings,

        [Parameter(Mandatory = $false)]
        [string[]]$AllowedSeverities = @("Critical", "High", "Medium", "Low")
    )


function Format-WrappedText {
    param(
        [string]$Text,
        [int]$Width = 120
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return "N/A"
    }

    $words = ($Text -replace '\r?\n',' ') -split '\s+'
    $lines = New-Object System.Collections.Generic.List[string]
    $current = ""

    foreach ($word in $words) {
        if (($current.Length + $word.Length + 1) -le $Width) {
            if ($current.Length -gt 0) {
                $current += " "
            }
            $current += $word
        }
        else {
            if ($current.Length -gt 0) {
                $lines.Add($current)
            }
            $current = $word
        }
    }

    if ($current.Length -gt 0) {
        $lines.Add($current)
    }

    return ($lines -join "`r`n")
}
    
    $activeFindings = $Findings | Where-Object { 
        $sev = $_.Severity
        if (-not $sev) { $sev = $_.sev }
        $sev -in $AllowedSeverities -and $sev -ne "Info" -and $sev -ne "Information" 
    }

    $SeverityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4 }
    $sortedFindings = @($activeFindings | Sort-Object { 
        $sev = $_.Severity; if (-not $sev) { $sev = $_.sev }
        if ($SeverityOrder.ContainsKey($sev)) { $SeverityOrder[$sev] } else { 99 }
    }, Category, Title)

    $results = foreach ($finding in $sortedFindings) {
        $modName = if ($finding.ModuleName) { $finding.ModuleName } 
                   elseif ($finding.Module) { $finding.Module } 
                   elseif ($finding.Source) { $finding.Source } 
                   else { "Unknown" }

        $severity = if ($finding.Severity) { $finding.Severity } elseif ($finding.sev) { $finding.sev } else { "UNKNOWN" }
        
        $category = if ($finding.Category) { $finding.Category } else { "General" }
        $type     = if ($finding.Type) { $finding.Type } else { "Specific" }
        $rawImpact = if ($finding.Impact) { $finding.Impact } else { "N/A" }
        $rawDesc   = if ($finding.Description) { $finding.Description } else { "N/A" }
        $rawVar    = if ($finding.VariableGuide) { $finding.VariableGuide } else { "N/A" }
        $code      = if ($finding.Code) { $finding.Code } 
                     elseif ($finding.RemediationCode) { $finding.RemediationCode } 
                     elseif ($finding.Remediation) { $finding.Remediation } 
                     else { "# No code provided" }

        if ($Global:WinFlesher -and $Global:WinFlesher.Modules) {
            $matchedModuleKey = $null
            $cleanModName = $modName -replace '\.ps1$', ''

            foreach ($k in $Global:WinFlesher.Modules.Keys) {
                $cleanKey = $k -replace '\.ps1$', ''
                if ($cleanKey -ieq $cleanModName) {
                    $matchedModuleKey = $k
                    break
                }
            }

            if ($matchedModuleKey) {
                $m = $Global:WinFlesher.Modules[$matchedModuleKey]
                if ($m) {
                    $remObj = if ($m.Remediation) { $m.Remediation } else { $m }
                    
                    if ($remObj.Category)      { $category  = $remObj.Category }
                    if ($remObj.Type)          { $type      = $remObj.Type }
                    if ($remObj.Impact)        { $rawImpact = $remObj.Impact }
                    if ($remObj.Description)   { $rawDesc   = $remObj.Description }
                    if ($remObj.VariableGuide) { $rawVar    = $remObj.VariableGuide }
                    if ($remObj.Code)          { $code      = $remObj.Code }
                    elseif ($m.Code)           { $code      = $m.Code }
                }
            }
        }

$impactWrapped = Format-WrappedText -Text $rawImpact -Width 120
$desc          = Format-WrappedText -Text $rawDesc -Width 120
$varGuide      = Format-WrappedText -Text $rawVar -Width 120
$codeWrapped = Format-WrappedText -Text $code -Width 120
$formattedBlock = @"

========================================================================================================================
[$severity] $modName
========================================================================================================================

Category
--------
$category

Type
----
$type

Impact
------
$impactWrapped

Description
-----------
$desc

Variable Guide
--------------
$varGuide

Remediation Script
------------------

$codeWrapped

========================================================================================================================

"@

        [PSCustomObject]@{
            Module         = $modName
            Severity       = $severity
            Category       = $category
            FormattedBlock = $formattedBlock
        }
    }

    return $results
}
