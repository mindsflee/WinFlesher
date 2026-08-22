<#
.SYNOPSIS
    Winflesher - Attack Surface Security Framework by mindsflee (Alessandro Salzano)
.DESCRIPTION
    Winflesher is an advanced attack surface security assessment framework designed 
    to analyze, evaluate, and report on security postures, attack paths, and 
    remediation strategies.
.NOTE
    Main entry point loader for the Winflesher framework.
#>

$ErrorActionPreference = "Stop"

try
{
    $BasePath = Split-Path -Parent $MyInvocation.MyCommand.Path

    $LocalModulesPath = Join-Path $BasePath "Modules"
    if (Test-Path $LocalModulesPath) {
        $env:PSModulePath = "$LocalModulesPath;$env:PSModulePath"
    }

    Write-Host "[*] WinFlesher bootstrap starting..." -ForegroundColor Cyan

    $ExecutionPolicy = Get-ExecutionPolicy
    if ($ExecutionPolicy -eq "Restricted")
    {
        throw "ExecutionPolicy is Restricted. Enable at least RemoteSigned."
    }
    Write-Host "[OK] Execution Policy: $ExecutionPolicy" -ForegroundColor Green

    $ADModule = Get-Module -ListAvailable ActiveDirectory
    if (-not $ADModule)
    {
        throw @"
ActiveDirectory PowerShell module not found.
Install RSAT AD Tools:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
"@
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "[OK] ActiveDirectory module loaded" -ForegroundColor Green

    $RequiredFiles = @("$BasePath\Core\Core.ps1", "$BasePath\Lib\Export.ps1", "$BasePath\Core\Gui.ps1")
    foreach ($File in $RequiredFiles)
    {
        if (-not (Test-Path $File)) { throw "Required file not found: $File" }
        Write-Host "[OK] Found $([IO.Path]::GetFileName($File))" -ForegroundColor Green
    }

    . "$BasePath\Core\Core.ps1"
    . "$BasePath\Lib\Export.ps1"
    . "$BasePath\Core\Gui.ps1"
    Write-Host "[OK] PowerShell files loaded" -ForegroundColor Green

    Write-Host ""
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host " WINFLESHER RUNTIME MODE" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host " [1] Launch Interactive GUI" -ForegroundColor White
    Write-Host " [2] Run Full Assessment & Export HTML/CSV/JSON (Headless)" -ForegroundColor White
    Write-Host ""
    
    $Choice = Read-Host "Select an option [1-2]"

    if ($Choice -eq "2") {
        Write-Host "[*] Starting automated assessment..." -ForegroundColor Cyan
        
        Start-WFLAssessment
        
        Write-Host "[*] Exporting findings and reports..." -ForegroundColor Cyan
        $ReportsPath = Join-Path $BasePath "Reports"
        if (-not (Test-Path $ReportsPath)) {
            New-Item -ItemType Directory -Path $ReportsPath | Out-Null
        }
        
        Write-Host "[*] Generating exports..." -ForegroundColor Gray
        Export-WFLFindingsCsv -Path (Join-Path $ReportsPath "WinFlesher-Findings.csv")
        Export-WFLFindingsJson -Path (Join-Path $ReportsPath "WinFlesher-Findings.json")
        Export-WFLDetailsJson -Path (Join-Path $ReportsPath "WinFlesher-Details.json")
        $HtmlReportPath = Export-WFLReportHtml -Folder $ReportsPath
        
        Write-Host "[OK] Assessment completed!" -ForegroundColor Green
        Write-Host "[OK] Reports saved in: $ReportsPath" -ForegroundColor Green
    }
    else {
        $GuiCommand = Get-Command Start-WFLGui -ErrorAction SilentlyContinue
        if (-not $GuiCommand) { throw "Start-WFLGui function not found after loading Gui.ps1" }
        
        Write-Host "[*] Starting WinFlesher GUI..." -ForegroundColor Cyan
        Start-WFLGui
    }
}
catch
{
    Write-Host ""
    Write-Host "[ERROR] $_" -ForegroundColor Red
    Write-Host ""
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "WinFlesher Startup Error", "OK", "Error") | Out-Null
}
