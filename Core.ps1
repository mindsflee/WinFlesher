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


$VersionFile = Join-Path $PSScriptRoot "..\version.json"

$VersionInfo = Get-Content $VersionFile -Raw | ConvertFrom-Json

$Global:WinFlesher = @{
    Version   = $VersionInfo.Version
    BuildDate = $VersionInfo.ReleaseDate

    UpdateUrl = "https://raw.githubusercontent.com/mindsflee/WinFlesher/main/version.json"

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
function Get-WFLUpdateInfo {
    try {
        if (
            -not $Global:WinFlesher.UpdateUrl -or
            [string]::IsNullOrWhiteSpace([string]$Global:WinFlesher.UpdateUrl)
        ) {
            throw "WinFlesher UpdateUrl is not configured."
        }

        $CacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        $RequestUri = "{0}?nocache={1}" -f `
            $Global:WinFlesher.UpdateUrl,
            $CacheBuster

        $Info = Invoke-RestMethod `
            -Uri $RequestUri `
            -UseBasicParsing `
            -Headers @{
                "Cache-Control" = "no-cache"
                "User-Agent"    = "WinFlesher-Updater"
            }

        $CurrentVersion = [version]$Global:WinFlesher.Version
        $RemoteVersion  = [version]$Info.Version

        [PSCustomObject]@{
            CurrentVersion  = $CurrentVersion
            RemoteVersion   = $RemoteVersion
            UpdateAvailable = ($RemoteVersion -gt $CurrentVersion)
            ReleaseDate     = $Info.ReleaseDate
            ReleaseNotes    = $Info.ReleaseNotes
            ZipUrl          = $Info.ZipUrl
        }
    }
    catch {
        Write-WFLLog `
            "Update check failed: $($_.Exception.Message)" `
            "WARN"

        return $null
    }
}

function Update-WFL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,

        [Parameter(Mandatory)]
        [object]$UpdateInfo
    )

    $TempRoot    = Join-Path $env:TEMP ("WinFlesher_Update_{0}" -f ([guid]::NewGuid().ToString("N")))
    $TempZip     = Join-Path $TempRoot "WinFlesher_Update.zip"
    $ExtractPath = Join-Path $TempRoot "Extracted"
    $BackupStage = Join-Path $TempRoot "BackupStage"

    try {
        if (-not (Test-Path -LiteralPath $BasePath -PathType Container)) {
            throw "WinFlesher base path not found: $BasePath"
        }

        if (-not $UpdateInfo.UpdateAvailable) {
            Write-WFLLog "WinFlesher is already up to date." "OK"
            return $false
        }

        if ([string]::IsNullOrWhiteSpace([string]$UpdateInfo.ZipUrl)) {
            throw "ZipUrl is missing from version.json."
        }

        $ZipUri = $null

        if (-not [System.Uri]::TryCreate(
            [string]$UpdateInfo.ZipUrl,
            [System.UriKind]::Absolute,
            [ref]$ZipUri
        )) {
            throw "Invalid ZipUrl in version.json."
        }

        if ($ZipUri.Scheme -ne "https") {
            throw "The update package must use HTTPS."
        }

        if ($ZipUri.Host -notin @(
            "github.com",
            "codeload.github.com"
        )) {
            throw "Update download host is not allowed: $($ZipUri.Host)"
        }

        Write-WFLLog "Preparing update to version $($UpdateInfo.RemoteVersion)..." "INFO"

        New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null
        New-Item -ItemType Directory -Path $BackupStage -Force | Out-Null

        Write-WFLLog "Downloading update package..." "INFO"

        Invoke-WebRequest `
            -Uri $UpdateInfo.ZipUrl `
            -OutFile $TempZip `
            -UseBasicParsing `
            -ErrorAction Stop

        if (-not (Test-Path -LiteralPath $TempZip -PathType Leaf)) {
            throw "The update package was not downloaded."
        }

        if ((Get-Item -LiteralPath $TempZip).Length -eq 0) {
            throw "The downloaded update package is empty."
        }

        Write-WFLLog "Extracting update package..." "INFO"

        Expand-Archive `
            -LiteralPath $TempZip `
            -DestinationPath $ExtractPath `
            -Force `
            -ErrorAction Stop

        $RepoRoot = Get-ChildItem `
            -LiteralPath $ExtractPath `
            -Directory `
            -ErrorAction Stop |
            Select-Object -First 1

        if (-not $RepoRoot) {
            throw "Unable to locate the repository root in the update package."
        }

        $RequiredUpdateFiles = @(
            (Join-Path $RepoRoot.FullName "Core\Core.ps1"),
            (Join-Path $RepoRoot.FullName "Lib\Export.ps1"),
            (Join-Path $RepoRoot.FullName "Invoke-Winflesher.ps1"),
            (Join-Path $RepoRoot.FullName "version.json")
        )

        foreach ($RequiredFile in $RequiredUpdateFiles) {
            if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
                throw "Invalid update package. Required file not found: $RequiredFile"
            }
        }

        $PackageVersionFile = Join-Path $RepoRoot.FullName "version.json"

        try {
            $PackageVersionInfo = Get-Content `
                -LiteralPath $PackageVersionFile `
                -Raw `
                -ErrorAction Stop |
                ConvertFrom-Json `
                    -ErrorAction Stop

            $PackageVersion = [version]$PackageVersionInfo.Version
        }
        catch {
            throw "Unable to validate the version.json contained in the update package: $($_.Exception.Message)"
        }

        if ($PackageVersion -ne [version]$UpdateInfo.RemoteVersion) {
            throw "Update package version mismatch. Expected $($UpdateInfo.RemoteVersion), found $PackageVersion."
        }

        #
        # BACKUP CREATION
        # Reports and local backup folders are excluded from the backup package stage.
        #

        Write-WFLLog "Creating backup of the current installation..." "INFO"

        $BackupFolder = Join-Path $BasePath "Backup"

        if (-not (Test-Path -LiteralPath $BackupFolder)) {
            New-Item `
                -ItemType Directory `
                -Path $BackupFolder `
                -Force |
                Out-Null
        }

        $BackupItems = Get-ChildItem `
            -LiteralPath $BasePath `
            -Force `
            -ErrorAction Stop |
            Where-Object {
                $_.Name -notin @(
                    "Backup",
                    "Reports"
                )
            }

        if (-not $BackupItems) {
            throw "No files were found to include in the backup."
        }

        foreach ($Item in $BackupItems) {
            Copy-Item `
                -LiteralPath $Item.FullName `
                -Destination $BackupStage `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }

        $BackupZip = Join-Path `
            $BackupFolder `
            ("WinFlesher_Backup_v{0}_{1}.zip" -f `
                $Global:WinFlesher.Version,
                (Get-Date -Format "yyyyMMdd_HHmmss"))

        Compress-Archive `
            -Path (Join-Path $BackupStage "*") `
            -DestinationPath $BackupZip `
            -CompressionLevel Optimal `
            -Force `
            -ErrorAction Stop

        if (-not (Test-Path -LiteralPath $BackupZip -PathType Leaf)) {
            throw "Backup creation failed."
        }

        Write-WFLLog "Backup created: $BackupZip" "OK"

        #
        # DYNAMIC UPDATE BASED ON EXCLUSIONS
        # Copies everything from the extracted package root except local runtime/state paths.
        # This ensures newly added directories or files are automatically included in updates.
        #

        $ExcludedItems = @(
            "Backup",
            "Reports",
            ".git",
            ".github"
        )

        $PackageItems = Get-ChildItem -LiteralPath $RepoRoot.FullName -Force

        foreach ($Item in $PackageItems) {
            if ($Item.Name -in $ExcludedItems) {
                continue
            }

            $TargetItemPath = Join-Path $BasePath $Item.Name

            Copy-Item `
                -LiteralPath $Item.FullName `
                -Destination $TargetItemPath `
                -Recurse `
                -Force `
                -ErrorAction Stop

            if ($Item.PSIsContainer) {
                Write-WFLLog "Updated folder: $($Item.Name)" "OK"
            }
            else {
                Write-WFLLog "Updated file: $($Item.Name)" "OK"
            }
        }

        Write-WFLLog "WinFlesher updated successfully to version $PackageVersion." "OK"
        Write-WFLLog "Restart WinFlesher to load the updated files." "WARN"

        return $true
    }
    catch {
        Write-WFLLog "Update failed: $($_.Exception.Message)" "ERROR"
        Write-WFLLog "The current installation backup, if created, is available under: $(Join-Path $BasePath 'Backup')" "WARN"

        return $false
    }
    finally {
        if (Test-Path -LiteralPath $TempRoot) {
            Remove-Item `
                -LiteralPath $TempRoot `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
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
            "Critical" { $Score -= 5 }
            "High"     { $Score -= 2.5 }
            "Medium"   { $Score -= 0.50 }
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
        $Rating = "Medium"
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

