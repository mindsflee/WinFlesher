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
# Remove Mark-of-the-Web from all WinFlesher files
try {
    Write-Host "[*] Removing Internet zone markers..." -ForegroundColor Cyan

    Get-ChildItem $BasePath -Recurse -File -ErrorAction SilentlyContinue |
        Unblock-File -ErrorAction SilentlyContinue

    Write-Host "[OK] Files unblocked" -ForegroundColor Green
}
catch {
    Write-Host "[WARN] Unable to unblock some files" -ForegroundColor Yellow
}
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
    
    #
    # AUTOMATIC UPDATE CHECK
    #

    $UpdateInfo = Get-WFLUpdateInfo

    if ($UpdateInfo) {
        Write-Host ""
        Write-Host "[VERSION] Current: $($UpdateInfo.CurrentVersion)" -ForegroundColor Gray

        if ($UpdateInfo.UpdateAvailable) {
            Write-Host "[UPDATE] New version available: $($UpdateInfo.RemoteVersion)" -ForegroundColor Yellow

            if ($UpdateInfo.ReleaseDate) {
                Write-Host "[UPDATE] Release date: $($UpdateInfo.ReleaseDate)" -ForegroundColor Gray
            }

            if ($UpdateInfo.ReleaseNotes) {
                Write-Host "[UPDATE] $($UpdateInfo.ReleaseNotes)" -ForegroundColor Gray
            }

            Write-Host ""

            $UpdateChoice = Read-Host "Download and install the update now? [Y/N]"

            if ($UpdateChoice -match "^(Y|YES|S|SI)$") {
                Write-Host ""
                Write-Host "[*] Starting WinFlesher update..." -ForegroundColor Cyan

                $UpdateResult = Update-WFL `
                    -BasePath $BasePath `
                    -UpdateInfo $UpdateInfo

                Write-Host ""

                if ($UpdateResult) {
                    Write-Host "[OK] Update completed successfully." -ForegroundColor Green
                    Write-Host "[*] WinFlesher must now be restarted." -ForegroundColor Yellow
                }
                else {
                    Write-Host "[ERROR] Update was not completed." -ForegroundColor Red
                    Write-Host "[*] Check the messages above and the Backup folder." -ForegroundColor Yellow
                }

                return
            }

            Write-Host "[*] Update skipped. Continuing with version $($UpdateInfo.CurrentVersion)." -ForegroundColor Yellow
        }
        else {
            Write-Host "[OK] WinFlesher is up to date." -ForegroundColor Green
        }

        Write-Host ""
    }
    
    Write-Host ""
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host " WINFLESHER RUNTIME MODE" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host " [1] Launch Interactive GUI" -ForegroundColor White
    Write-Host " [2] Run Full Assessment & Export HTML/CSV/JSON (Headless)" -ForegroundColor White
    Write-Host " [3] Authenticate with Microsoft Entra ID (Azure AD)" -ForegroundColor White
    Write-Host " [4] Update WinFlesher" -ForegroundColor White
    Write-Host ""
    
    $Choice = Read-Host "Select an option [1-4]"
    
    if ($Choice -eq "4") {
        Write-Host ""
        Write-Host "[*] Checking for updates..." -ForegroundColor Cyan

        $ManualUpdateInfo = Get-WFLUpdateInfo

        if (-not $ManualUpdateInfo) {
            Write-Host "[ERROR] Unable to retrieve update information." -ForegroundColor Red
            return
        }

        if (-not $ManualUpdateInfo.UpdateAvailable) {
            Write-Host "[OK] WinFlesher is already up to date." -ForegroundColor Green
            return
        }

        Write-Host "[UPDATE] Current version: $($ManualUpdateInfo.CurrentVersion)" -ForegroundColor Gray
        Write-Host "[UPDATE] New version: $($ManualUpdateInfo.RemoteVersion)" -ForegroundColor Yellow
        Write-Host ""

        $ManualChoice = Read-Host "Download and install the update now? [Y/N]"

        if ($ManualChoice -notmatch "^(Y|YES|S|SI)$") {
            Write-Host "[*] Update cancelled." -ForegroundColor Yellow
            return
        }

        $UpdateResult = Update-WFL `
            -BasePath $BasePath `
            -UpdateInfo $ManualUpdateInfo

        Write-Host ""

        if ($UpdateResult) {
            Write-Host "[OK] Update completed successfully." -ForegroundColor Green
            Write-Host "[*] Restart WinFlesher to load the new version." -ForegroundColor Yellow
        }
        else {
            Write-Host "[ERROR] Update was not completed." -ForegroundColor Red
        }

        return
    }

    if ($Choice -eq "3") {
        Write-Host ""
        Write-Host "[*] Preparing Microsoft Entra ID authentication via Device Code..." -ForegroundColor Cyan

        $hasGraph = Get-Module -ListAvailable -Name "Microsoft.Graph.Applications" -ErrorAction SilentlyContinue
        $hasAzureAD = Get-Module -ListAvailable -Name "AzureAD" -ErrorAction SilentlyContinue

        if (-not $hasGraph -and -not $hasAzureAD) {
            Write-Host "[ERROR] Required modules (Microsoft.Graph.Applications or AzureAD) are not installed." -ForegroundColor Red
            Write-Host "[*] Run: Install-Module Microsoft.Graph.Applications" -ForegroundColor Yellow
            return
        }

        try {
            if (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) {
                Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -UseDeviceCode -NoWelcome
                $ctx = Get-MgContext
                if ($ctx) {
                    Write-Host "[OK] Successfully connected to Entra ID Tenant: $($ctx.TenantId) as $($ctx.Account). Please restart WinFlesher." -ForegroundColor Green
                }
            } 
            elseif (Get-Command Connect-AzureAD -ErrorAction SilentlyContinue) {
                Write-Warning "AzureAD module does not natively support an interactive Device Code flow. Consider migrating to Microsoft.Graph."
                Connect-AzureAD | Out-Null
                $session = Get-AzureADCurrentSessionInfo
                if ($session) {
                    Write-Host "[OK] Successfully connected to AzureAD Tenant: $($session.TenantDomain). Please restart WinFlesher." -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "[ERROR] Cloud Connect Exception: $_" -ForegroundColor Red
        }
        return
    }

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
    try {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "WinFlesher Startup Error", "OK", "Error") | Out-Null
    }
    catch {}
}