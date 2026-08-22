<#
.SYNOPSIS
    Winflesher - Attack Surface Security Framework by mindsflee (Alessandro Salzano)
.DESCRIPTION
    Winflesher is an advanced attack surface security assessment framework designed 
    to analyze, evaluate, and report on security postures, attack paths, and 
    remediation strategies.
.COMPONENT
    Core Engine Module - [Core.ps1]
#>


$Global:WinFlesher = @{
    Version   = "2.0"
    RootPath  = $PSScriptRoot
    Context   = @{}
    Findings  = New-Object System.Collections.ArrayList
    Details   = @{}
    Modules   = @{}
    StartedAt = Get-Date
}


function Write-WFLLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","MODULE","DISCOVERY")]
        [string]$Level = "INFO"
    )

    $Color = "Gray"

    switch ($Level) {
        "OK"        { $Color = "Green" }
        "WARN"      { $Color = "Yellow" }
        "ERROR"     { $Color = "Red" }
        "MODULE"    { $Color = "Cyan" }
        "DISCOVERY" { $Color = "Yellow" }
    }

    $Timestamp = Get-Date -Format "HH:mm:ss"
	Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
}


function Add-WFLFinding {

    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [ValidateSet("Critical","High","Medium","Low","Info")]
        [string]$Severity = "Info",

        [string]$Category = "General",
        [string]$MITRE = "",
        [string]$Tactic = "",
        [string]$Evidence = "",
        [string]$Recommendation = "",
        [string]$Source = "",
        [string]$Impact = ""
    )

    if (
        [string]::IsNullOrEmpty($Impact) -and
        -not [string]::IsNullOrEmpty($Source)
    ) {

        if (
            $Global:WinFlesher.Modules -and
            $Global:WinFlesher.Modules.ContainsKey($Source)
        ) {

            $Impact = $Global:WinFlesher.Modules[$Source].Impact
        }
    }

    $Finding = [PSCustomObject]@{
        Time           = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Severity       = $Severity
        Category       = $Category
        MITRE          = $MITRE
        Tactic         = $Tactic
        Impact         = $Impact
        Title          = $Title
        Evidence       = $Evidence
        Recommendation = $Recommendation
        Source         = $Source
    }

    [void]$Global:WinFlesher.Findings.Add($Finding)
}

function Clear-WFLFindings {
    $Global:WinFlesher.Findings.Clear()
}

function Show-WFLFindings {
    param(
        [ValidateSet("Critical","High","Medium","Low","Info")]
        [string]$Severity
    )

    $Data = $Global:WinFlesher.Findings

    if ($Severity) {
        $Data = $Data | Where-Object { $_.Severity -eq $Severity }
    }

    $Data |
        Sort-Object Severity, Category, Title |
        Format-Table Severity, Category, MITRE, Title, Source -AutoSize
}

function Show-WFLFindingDetails {
    param(
        [int]$Index = 0
    )

    if ($Global:WinFlesher.Findings.Count -eq 0) {
        Write-WFLLog "No findings available." "WARN"
        return
    }

    if ($Index -lt 0 -or $Index -ge $Global:WinFlesher.Findings.Count) {
        Write-WFLLog "Invalid finding index." "ERROR"
        return
    }

    $Global:WinFlesher.Findings[$Index] | Format-List *
}


function Add-WFLDetail {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object]$Data
    )

    $Global:WinFlesher.Details[$Name] = @($Data)
}

function Show-WFLDetails {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Global:WinFlesher.Details.ContainsKey($Name)) {
        Write-WFLLog "No details found for: $Name" "WARN"
        return
    }

    $Global:WinFlesher.Details[$Name]
}

function Show-WFLDetailNames {
    $Global:WinFlesher.Details.Keys | Sort-Object
}

function Clear-WFLDetails {
    $Global:WinFlesher.Details.Clear()
}


function Register-WFLModule {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Category = "General",

        [ValidateSet("Check","Discovery","Validation","Report","Utility")]
        [string]$Type = "Check",

        [string]$MITRE = "",
        [string]$Tactic = "",
        [string]$Description = "",

        
        [string]$Impact = "",
		[hashtable]$Remediation = $null,

        [Parameter(Mandatory)]
        [scriptblock]$Run
    )


	
$Global:WinFlesher.Modules[$Name] = [PSCustomObject]@{
    Name         = $Name
    Category     = $Category
    Type         = $Type
    MITRE        = $MITRE
    Tactic       = $Tactic
    Impact       = $Impact
    Description  = $Description
    Remediation  = $Remediation
    Run          = $Run
}

}

function Get-WFLModules {
    $Global:WinFlesher.Modules.Values |
        Sort-Object Category, Name |
        Select-Object Name, Category, Type, MITRE, Tactic, Impact, Description
}

function Show-WFLModules {
    Get-WFLModules | Format-Table -AutoSize
}

function Show-WFLModule {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Global:WinFlesher.Modules.ContainsKey($Name)) {
        Write-WFLLog "Module not found: $Name" "ERROR"
        return
    }

    $Global:WinFlesher.Modules[$Name] |
        Format-List Name, Category, Type, MITRE, Tactic, Impact, Description
}

function Search-WFLModule {
    param(
        [string]$Keyword,
        [string]$Category,
        [string]$MITRE
    )

    $Modules = $Global:WinFlesher.Modules.Values

    if ($Keyword) {
        $Modules = $Modules | Where-Object {
            $_.Name -like "*$Keyword*" -or
            $_.Description -like "*$Keyword*" -or
            $_.Category -like "*$Keyword*" -or
            $_.MITRE -like "*$Keyword*" -or
            $_.Tactic -like "*$Keyword*"
        }
    }

    if ($Category) {
        $Modules = $Modules | Where-Object { $_.Category -like "*$Category*" }
    }

    if ($MITRE) {
        $Modules = $Modules | Where-Object { $_.MITRE -like "*$MITRE*" }
    }

    $Modules |
        Sort-Object Category, Name |
        Select-Object Name, Category, Type, MITRE, Tactic, Impact, Description
}

function Invoke-WFLModule {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Global:WinFlesher.Modules.ContainsKey($Name)) {
        Write-WFLLog "Module not found: $Name" "ERROR"
        return
    }

    $Module = $Global:WinFlesher.Modules[$Name]

    Write-WFLLog "Running module: $($Module.Name)" "MODULE"

    try {
        & $Module.Run
    }
    catch {
        Add-WFLFinding `
            -Title "Module execution failed: $($Module.Name)" `
            -Severity "Medium" `
            -Category "Framework" `
            -Source $Module.Name `
            -Evidence $_.Exception.Message `
            -Recommendation "Review module code, permissions, and discovery context."
    }
}

function Invoke-WFLAllModules {
    foreach ($Module in $Global:WinFlesher.Modules.Values | Sort-Object Category, Name) {
        Invoke-WFLModule -Name $Module.Name
    }
}


function Invoke-WFLDiscovery {
    Write-WFLLog "Discovery started" "DISCOVERY"

    $Context = @{}

    try {
        $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $CS = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

        $Context.Host = [PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            UserName       = $env:USERNAME
            UserDomain     = $env:USERDOMAIN
            IsDomainJoined = [bool]$CS.PartOfDomain
            Domain         = $CS.Domain
            Manufacturer   = $CS.Manufacturer
            Model          = $CS.Model
            OS             = $OS.Caption
            Build          = $OS.BuildNumber
            InstallDate    = $OS.InstallDate
            LastBoot       = $OS.LastBootUpTime
        }
    }
    catch {
        $Context.Host = [PSCustomObject]@{
            Error = $_.Exception.Message
        }
    }

    try {
        $Context.Network = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
    }
    catch {
        $Context.Network = @()
    }

    try {
        $Context.Services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    }
    catch {
        $Context.Services = @()
    }

    try {
        $Context.ScheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Select-Object TaskName, TaskPath, State, Author
    }
    catch {
        $Context.ScheduledTasks = @()
    }

    try {
        $Context.LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
            Select-Object Name, ObjectClass, PrincipalSource
    }
    catch {
        $Context.LocalAdmins = @()
    }

    try {
        $Context.Firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    }
    catch {
        $Context.Firewall = @()
    }

    $Context.LSA = @{}

    try {
        $LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $Context.LSA.RunAsPPL = (Get-ItemProperty -Path $LsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    }
    catch {
        $Context.LSA.RunAsPPL = $null
    }

    try {
        $WDigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        $Context.LSA.WDigestUseLogonCredential = (Get-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    }
    catch {
        $Context.LSA.WDigestUseLogonCredential = $null
    }

    $Context.Logging = @{}

    try {
        $SBL = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        $Context.Logging.PowerShellScriptBlockLogging = $SBL.EnableScriptBlockLogging
    }
    catch {
        $Context.Logging.PowerShellScriptBlockLogging = $null
    }

    try {
        $ML = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
        $Context.Logging.PowerShellModuleLogging = [bool]$ML
    }
    catch {
        $Context.Logging.PowerShellModuleLogging = $false
    }

    try {
        $WmiLog = Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational" -ErrorAction SilentlyContinue
        $Context.Logging.WMIActivityOperational = $WmiLog.IsEnabled
    }
    catch {
        $Context.Logging.WMIActivityOperational = $null
    }

    try {
        $MP = Get-MpComputerStatus -ErrorAction SilentlyContinue

        if ($MP) {
            $Context.Defender = [PSCustomObject]@{
                Available                 = $true
                AMServiceEnabled          = $MP.AMServiceEnabled
                AntivirusEnabled          = $MP.AntivirusEnabled
                RealTimeProtectionEnabled = $MP.RealTimeProtectionEnabled
                BehaviorMonitorEnabled    = $MP.BehaviorMonitorEnabled
                IoavProtectionEnabled     = $MP.IoavProtectionEnabled
                NISEnabled                = $MP.NISEnabled
                IsTamperProtected         = $MP.IsTamperProtected
            }
        }
        else {
            $Context.Defender = [PSCustomObject]@{
                Available = $false
            }
        }
    }
    catch {
        $Context.Defender = [PSCustomObject]@{
            Available = $false
            Error     = $_.Exception.Message
        }
    }

    $Context.ActiveDirectory = [PSCustomObject]@{
        Available = $false
    }

    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop

            $Domain = Get-ADDomain -ErrorAction Stop
            $Forest = Get-ADForest -ErrorAction Stop

            $Context.ActiveDirectory = [PSCustomObject]@{
                Available            = $true
                DomainName           = $Domain.DNSRoot
                NetBIOSName          = $Domain.NetBIOSName
                DomainMode           = $Domain.DomainMode
                Forest               = $Forest.Name
                ForestMode           = $Forest.ForestMode
                PDCEmulator          = $Domain.PDCEmulator
                RIDMaster            = $Domain.RIDMaster
                InfrastructureMaster = $Domain.InfrastructureMaster
            }

            $Context.ADDomainControllers = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue |
                Select-Object HostName, Site, OperatingSystem, IsGlobalCatalog, IPv4Address

            $Context.ADUsersWithSPN = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" `
                -Properties servicePrincipalName, PasswordLastSet, PasswordNeverExpires, AdminCount, Enabled, msDS-SupportedEncryptionTypes `
                -ErrorAction SilentlyContinue |
                Select-Object SamAccountName, Enabled, PasswordLastSet, PasswordNeverExpires, AdminCount, msDS-SupportedEncryptionTypes, DistinguishedName

            $PrivGroups = @(
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins",
                "Administrators",
                "Account Operators",
                "Server Operators",
                "Backup Operators"
            )

            $PrivMembers = @()

            foreach ($Group in $PrivGroups) {
                try {
                    $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction Stop |
                        Select-Object @{Name="Group";Expression={$Group}}, Name, SamAccountName, ObjectClass

                    $PrivMembers += $Members
                }
                catch {}
            }

            $Context.ADPrivilegedGroupMembers = $PrivMembers
        }
    }
    catch {
        $Context.ActiveDirectory = [PSCustomObject]@{
            Available = $false
            Error     = $_.Exception.Message
        }
    }

    $Global:WinFlesher.Context = $Context

    Write-WFLLog "Discovery completed" "OK"

    return $Context
}

function Show-WFLContext {
    $Global:WinFlesher.Context
}


function Get-WFLScore {

    $Score = 100

    foreach($Finding in $Global:WinFlesher.Findings)
    {
        switch($Finding.Severity)
        {
            "Critical" { $Score -= 10 }
            "High"     { $Score -= 5 }
            "Medium"   { $Score -= 2 }
            "Low"      { $Score -= 0.25 }
        }
    }

    if($Score -lt 0)
    {
        $Score = 0
    }

    $Critical = @(
        $Global:WinFlesher.Findings |
        Where-Object { $_.Severity -eq "Critical" }
    ).Count

    $High = @(
        $Global:WinFlesher.Findings |
        Where-Object { $_.Severity -eq "High" }
    ).Count

    $Medium = @(
        $Global:WinFlesher.Findings |
        Where-Object { $_.Severity -eq "Medium" }
    ).Count

    $Low = @(
        $Global:WinFlesher.Findings |
        Where-Object { $_.Severity -eq "Low" }
    ).Count

    $Info = @(
        $Global:WinFlesher.Findings |
        Where-Object { $_.Severity -eq "Info" }
    ).Count

    $Rating = "Very Good"

    if($Score -lt 50)
    {
        $Rating = "Critical"
    }
    elseif($Score -lt 70)
    {
        $Rating = "Weak"
    }
    elseif($Score -lt 85)
    {
        $Rating = "Good"
    }

    [PSCustomObject]@{
        Score    = $Score
        Rating   = $Rating
        Findings = $Global:WinFlesher.Findings.Count
        Critical = $Critical
        High     = $High
        Medium   = $Medium
        Low      = $Low
        Info     = $Info
    }
}

function Get-WFLSummaryByCategory {

    $Global:WinFlesher.Findings |
    Group-Object Category |
    ForEach-Object {

        $Critical = @(
            $_.Group |
            Where-Object { $_.Severity -eq "Critical" }
        ).Count

        $High = @(
            $_.Group |
            Where-Object { $_.Severity -eq "High" }
        ).Count

        $Medium = @(
            $_.Group |
            Where-Object { $_.Severity -eq "Medium" }
        ).Count

        $Low = @(
            $_.Group |
            Where-Object { $_.Severity -eq "Low" }
        ).Count

        $Info = @(
            $_.Group |
            Where-Object { $_.Severity -eq "Info" }
        ).Count

        [PSCustomObject]@{
            Category = $_.Name
            Critical = $Critical
            High     = $High
            Medium   = $Medium
            Low      = $Low
            Info     = $Info
            Total    = $_.Count
        }
    } |
    Sort-Object Category
}


function Start-WFLAssessment {
    param(
        [switch]$NoDiscovery
    )

    Clear-WFLFindings
    Clear-WFLDetails

    if (-not $NoDiscovery) {
        Invoke-WFLDiscovery | Out-Null
    }

    Invoke-WFLAllModules

    Get-WFLScore
}


function Import-WFLModules {
    $Global:WinFlesher.Modules.Clear()

    $ModulePath = Join-Path $PSScriptRoot "..\Modules"

    if (-not (Test-Path $ModulePath)) {
        Write-WFLLog "Modules folder not found: $ModulePath" "WARN"
        return
    }

    Get-ChildItem -Path $ModulePath -Filter "*.ps1" -File |
        Sort-Object Name |
        ForEach-Object {
            try {
                . $_.FullName
                Write-WFLLog "Loaded module file: $($_.Name)" "OK"
            }
            catch {
                Write-WFLLog "Failed to load module file $($_.Name): $($_.Exception.Message)" "ERROR"
            }
        }
}


function Export-WFLFindingsCsv {
    param(
        [string]$Path = ".\WinFlesher-Findings.csv"
    )

    $Global:WinFlesher.Findings |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

    Write-WFLLog "CSV exported: $Path" "OK"
}

function Export-WFLFindingsJson {
    param(
        [string]$Path = ".\WinFlesher-Findings.json"
    )

    $Global:WinFlesher.Findings |
        ConvertTo-Json -Depth 8 |
        Set-Content -Path $Path -Encoding UTF8

    Write-WFLLog "JSON exported: $Path" "OK"
}

function Export-WFLDetailsJson {
    param(
        [string]$Path = ".\WinFlesher-Details.json"
    )

    $Global:WinFlesher.Details |
        ConvertTo-Json -Depth 8 |
        Set-Content -Path $Path -Encoding UTF8

    Write-WFLLog "Details JSON exported: $Path" "OK"
}


$AttackPathsScript = Join-Path $PSScriptRoot "AttackPaths-Engine.ps1"
if (Test-Path $AttackPathsScript) {
    . $AttackPathsScript
}

$RemediationFile = Join-Path $PSScriptRoot "Remediation.ps1"

if (Test-Path $RemediationFile) {
    . $RemediationFile
    Write-Host "[+] Remediation module loaded" -ForegroundColor Green
}
else {
    Write-Warning "Remediation.ps1 not found: $RemediationFile"
}


Import-WFLModules

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host " WINFLESHER CORE LOADED" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Commands:" -ForegroundColor Gray
Write-Host "  Invoke-WFLDiscovery" -ForegroundColor Gray
Write-Host "  Show-WFLContext" -ForegroundColor Gray
Write-Host "  Show-WFLModules" -ForegroundColor Gray
Write-Host "  Show-WFLModule -Name <module>" -ForegroundColor Gray
Write-Host "  Search-WFLModule -Keyword <text>" -ForegroundColor Gray
Write-Host "  Start-WFLAssessment" -ForegroundColor Gray
Write-Host "  Show-WFLFindings" -ForegroundColor Gray
Write-Host "  Show-WFLDetailNames" -ForegroundColor Gray
Write-Host "  Show-WFLDetails -Name <detail>" -ForegroundColor Gray
Write-Host "  Get-WFLScore" -ForegroundColor Gray
Write-Host "  Get-WFLSummaryByCategory" -ForegroundColor Gray
Write-Host ""

