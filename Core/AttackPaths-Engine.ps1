<#
.SYNOPSIS
    Winflesher - Attack Surface Security Framework by mindsflee (Alessandro Salzano)
.DESCRIPTION
    Winflesher is an advanced attack surface security assessment framework designed 
    to analyze, evaluate, and report on security postures, attack paths, and 
    remediation strategies.
.COMPONENT
    Core Engine Module - [AttackPaths-Engine.ps1]
#>

function Show-AttackPaths {

    function Get-WFLField {
        param(
            [object]$Object,
            [string[]]$Names
        )

        foreach ($Name in $Names) {
            if ($null -eq $Object) {
                continue
            }

            $Prop = $Object.PSObject.Properties[$Name]

            if ($Prop -and $null -ne $Prop.Value) {
                $Value = "$($Prop.Value)".Trim()

                if ($Value.Length -gt 0) {
                    return $Value
                }
            }
        }

        return ""
    }

    function Write-WFLAttackOutput {
        param(
            [string]$Text
        )

        if (Get-Command Show-Text -ErrorAction SilentlyContinue) {
            Show-Text $Text
        }
        else {
            Write-Host $Text
        }
    }

    function Test-WFLAttackImpact {
        param(
            [string]$Impact
        )

        if ([string]::IsNullOrEmpty($Impact)) {
            return $false
        }

        if ($Impact -eq "NO ATTACK PATH IMPACT") {
            return $false
        }

        if ($Impact -notmatch "^POTENTIAL ") {
            return $false
        }

        return $true
    }

    function Get-WFLRiskFromImpact {
        param(
            [string]$Impact,
            [object[]]$Nodes
        )

        if ($Nodes | Where-Object { $_.Severity -eq "Critical" }) {
            return "CRITICAL"
        }

        switch ($Impact) {
            "POTENTIAL DOMAIN COMPROMISE" {
                return "CRITICAL"
            }

            "POTENTIAL PRIVILEGE ESCALATION" {
                return "HIGH"
            }

            "POTENTIAL CREDENTIAL COMPROMISE" {
                return "HIGH"
            }

            "POTENTIAL PERSISTENCE" {
                return "HIGH"
            }

            "POTENTIAL LATERAL MOVEMENT" {
                return "MEDIUM"
            }

            default {
                return "MEDIUM"
            }
        }
    }

function Get-WFLRiskFromImpact {
    param(
        [string]$Impact,
        [object[]]$Nodes
    )

    $Score = 0

    foreach ($Node in $Nodes) {

        switch ($Node.Severity) {

            "Critical" { $Score += 10 }
            "High"     { $Score += 6 }
            "Medium"   { $Score += 3 }
            "Low"      { $Score += 1 }
            default    { $Score += 0 }

        }
    }

  

    $ContextText = ($Nodes | ForEach-Object {
        "$($_.ModuleName) $($_.Title)"
    }) -join " "

    if (
        ($ContextText -match "Kerberoast|ASREP") -and
        ($ContextText -match "Delegation|RBCD")
    ) {
        $Score += 5
    }

    if (
        ($ContextText -match "DCSync") -and
        ($ContextText -match "Delegation|RBCD|AdminSDHolder")
    ) {
        $Score += 5
    }



    if ($ContextText -match "Golden Ticket|KRBTGT|DCSync|ESC4|ESC7|AdminSDHolder") {
        $Score = [int]($Score * 1.5)
    }

    

    if ($Score -ge 25) {
        return "CRITICAL"
    }

    if ($Score -ge 12) {
        return "HIGH"
    }

    if ($Score -ge 6) {
        return "MEDIUM"
    }

    if ($Score -ge 1) {
        return "LOW"
    }

    return "INFO"
}


   function Get-WFLRecommendedAction {
        param(
            [string]$Impact,
            [object[]]$Nodes
        )

        $ContextText = ($Nodes | ForEach-Object { "$($_.ModuleName) $($_.Title)" }) -join " "

        if ($ContextText -match "ADCS-|ESC") {
            return "Audit Certificate Authority ACLs, restrict template enrollment rights, disable vulnerable EKUs, and monitor for unauthorized certificate requests."
        }
        if ($ContextText -match "EntraID-|Cloud-") {
            return "Review cloud application permissions, enforce strict Conditional Access policies with mandatory MFA, and audit permanent privileged role assignments."
        }
        if ($ContextText -match "Kerberos|ASREP|Ticket|KRBTGT") {
            return "Enforce Kerberos pre-authentication, audit service principal names (SPNs), rotate compromised keys regularly, and harden ticket encryption standards."
        }
        if ($ContextText -match "Delegation|RBCD|AdminSDHolder|ShadowAdmins|DCSync") {
            return "Audit Active Directory access control lists (ACLs), restrict dangerous object delegations, enforce constrained delegation, and review privileged group memberships."
        }
        if ($ContextText -match "Service|Unquoted|AlwaysInstallElevated|TokenHijack") {
            return "Inspect local service binary permissions, fix unquoted service paths, restrict installation privileges, and audit local administrator memberships."
        }
        if ($ContextText -match "Persistence|WMI|Startup|Task") {
            return "Monitor system startup keys, inspect scheduled execution points, review persistent WMI subscriptions, and audit administrative script execution."
        }
        if ($ContextText -match "LSASS|LSA|WDigest|CredentialExposure") {
            return "Enable RunAsPPL process protection for LSASS, disable plaintext credential caching (WDigest), and clear exposed secrets from object descriptions."
        }
        if ($ContextText -match "Network|SMB|NTLM|Coercion|Trust") {
            return "Enforce SMB signing and LDAP channel binding, disable legacy protocols (NTLMv1, LLMNR/NetBIOS), and harden domain trust configurations."
        }

        switch ($Impact) {
            "POTENTIAL DOMAIN COMPROMISE" {
                return "Audit domain controller security configurations, check privileged group memberships, and enforce strict Tier-0 administrative access controls."
            }
            "POTENTIAL PRIVILEGE ESCALATION" {
                return "Review local administrative privileges, inspect insecure object permissions, and remediate service-based escalation vectors."
            }
            "POTENTIAL CREDENTIAL COMPROMISE" {
                return "Audit account authentication properties, enforce robust password policies, and protect sensitive caching or delegation mechanisms."
            }
            "POTENTIAL PERSISTENCE" {
                return "Inspect system startup points, scheduled tasks, registry run keys, and recurring execution scripts for hidden persistence hooks."
            }
            "POTENTIAL LATERAL MOVEMENT" {
                return "Enforce network segmentation, restrict remote management and protocol exposure across subnets, and monitor for unauthorized remote execution."
            }
            default {
                return "Validate exploitability, affected principals, and compensating controls."
            }
        }
    }

    function Format-WFLWrappedLines {
        param(
            [string]$Text,
            [int]$MaxWidth
        )

        if ([string]::IsNullOrEmpty($Text)) {
            return @("")
        }

        $Words = $Text -split '\s+'
        $Lines = [System.Collections.Generic.List[string]]::new()
        $CurrentLine = ""

        foreach ($Word in $Words) {
            if ([string]::IsNullOrEmpty($CurrentLine)) {
                $CurrentLine = $Word
            }
            elseif (($CurrentLine.Length + 1 + $Word.Length) -le $MaxWidth) {
                $CurrentLine += " " + $Word
            }
            else {
                $Lines.Add($CurrentLine)
                $CurrentLine = $Word
            }
        }

        if (-not [string]::IsNullOrEmpty($CurrentLine)) {
            $Lines.Add($CurrentLine)
        }

        return $Lines
    }

    function Add-WFLNode {
        param(
            [System.Collections.ArrayList]$Nodes,
            [string]$Title,
            [string]$Severity,
            [string]$Category,
            [string]$Impact,
            [string]$ModuleName,
            [string]$Entity,
            [bool]$Active
        )

        [void]$Nodes.Add([pscustomobject]@{
            Title      = $Title
            Severity   = $Severity
            Category   = $Category
            Impact     = $Impact
            ModuleName = $ModuleName
            Entity     = $Entity
            Active     = $Active
        })
    }

    try {
        $Builder = New-Object System.Text.StringBuilder

        [void]$Builder.AppendLine("+------------------------------------------------------------------------------+")
        [void]$Builder.AppendLine("|                     WINFLESHER IMPACT-BASED ATTACK PATH                      |")
        [void]$Builder.AppendLine("+------------------------------------------------------------------------------+")
        [void]$Builder.AppendLine("")

        if (-not $Global:WinFlesher -or -not $Global:WinFlesher.Findings) {
            [void]$Builder.AppendLine(" [!] No findings telemetry found. Run assessment sequence first.")
            Write-WFLAttackOutput $Builder.ToString()
            return
        }

        $Findings = @($Global:WinFlesher.Findings)

        if ($Findings.Count -eq 0) {
            [void]$Builder.AppendLine(" [+] No active findings available.")
            Write-WFLAttackOutput $Builder.ToString()
            return
        }

        $ModuleImpactMap = @{}

        if ($Global:WinFlesher.Modules) {
            $ModuleList = @()
            if ($Global:WinFlesher.Modules -is [hashtable]) {
                $ModuleList = @($Global:WinFlesher.Modules.Values)
            }
            else {
                $ModuleList = @($Global:WinFlesher.Modules)
            }

            foreach ($Module in $ModuleList) {
                if ($Module.Name -and $Module.Impact) {
                    $ModuleImpactMap["$($Module.Name)"] = "$($Module.Impact)"
                }
            }
        }

        $Nodes = New-Object System.Collections.ArrayList

        foreach ($Finding in $Findings) {
            $Title = Get-WFLField $Finding @("Title", "Name", "Finding", "Issue")
            $Severity = Get-WFLField $Finding @("Severity", "Risk", "Level")
            $Category = Get-WFLField $Finding @("Category", "Area", "Domain")
            $Impact = Get-WFLField $Finding @("Impact", "AttackPathImpact", "AttackPathCategory", "PathImpact")
            $ModuleName = Get-WFLField $Finding @("Module", "ModuleName", "SourceModule", "CheckName", "Check")
            $Entity = Get-WFLField $Finding @("Entity", "Target", "Object", "Account", "Computer", "Principal", "Asset")

            if (-not $Title) { $Title = "Unknown Finding" }
            if (-not $Severity) { $Severity = "Info" }
            if (-not $Category) { $Category = "Unclassified" }

            if ([string]::IsNullOrEmpty($Impact) -and -not [string]::IsNullOrEmpty($ModuleName) -and $ModuleImpactMap.ContainsKey($ModuleName)) {
                $Impact = $ModuleImpactMap[$ModuleName]
            }

            $Active = [bool]$true
            if ($Severity -match "Low|Info") { $Active = [bool]$false }
            if (-not (Test-WFLAttackImpact $Impact)) { $Active = [bool]$false }

            Add-WFLNode -Nodes $Nodes -Title $Title -Severity $Severity -Category $Category -Impact $Impact -ModuleName $ModuleName -Entity $Entity -Active $Active
        }

        $AllNodes = @($Nodes)
        $ScenarioNodes = @($AllNodes | Where-Object { $_.Active -eq $true -and $_.Severity -match "Critical|High|Medium" -and (Test-WFLAttackImpact $_.Impact) })

        [void]$Builder.AppendLine("   TELEMETRY NORMALIZED SUMMARY")
        [void]$Builder.AppendLine("   ├── Findings parsed : $($Findings.Count)")
        [void]$Builder.AppendLine("   ├── Attack nodes    : $($AllNodes.Count)")
        [void]$Builder.AppendLine("   └── Active nodes    : $($ScenarioNodes.Count)")
        [void]$Builder.AppendLine("--------------------------------------------------------------------------------")
        [void]$Builder.AppendLine("")

        $ImpactOrder = @(
            "POTENTIAL DOMAIN COMPROMISE",
            "POTENTIAL PRIVILEGE ESCALATION",
            "POTENTIAL CREDENTIAL COMPROMISE",
            "POTENTIAL PERSISTENCE",
            "POTENTIAL LATERAL MOVEMENT"
        )

        $ScenarioCount = 0

        foreach ($Impact in $ImpactOrder) {
            $ImpactNodes = @($ScenarioNodes | Where-Object { $_.Impact -eq $Impact } | Sort-Object Title -Unique)

            if ($ImpactNodes.Count -eq 0) { continue }

            $ScenarioCount++
            $Risk = Get-WFLRiskFromImpact -Impact $Impact -Nodes $ImpactNodes
            $ImpactDescription = Get-WFLImpactDescription -Impact $Impact

            $PrimaryAttackRisks = @($ImpactNodes | Where-Object { $_.Severity -match "Critical|High" } | Sort-Object Severity, Title -Descending)
            $ContributingConditions = @($ImpactNodes | Where-Object { $_.Severity -eq "Medium" } | Sort-Object Title)

            $ImpactHeaderContent = "     $Impact"
            [void]$Builder.AppendLine("+------------------------------------------------------------------------------+")
            [void]$Builder.AppendLine("|$($ImpactHeaderContent.PadRight(78))|")
            [void]$Builder.AppendLine("+------------------------------------------------------------------------------+")
            
            $RiskLine = "  • RISK LEVEL       : $Risk"
            [void]$Builder.AppendLine("|$($RiskLine.PadRight(78))|")
            
            $DescLines = Format-WFLWrappedLines -Text $ImpactDescription -MaxWidth 53
            foreach ($Line in $DescLines) {
                if ($Line -eq $DescLines[0]) {
                    $DescLine = "  • DESCRIPTION      : $Line"
                    [void]$Builder.AppendLine("|$($DescLine.PadRight(78))|")
                } else {
                    $DescLine = "                       $Line"
                    [void]$Builder.AppendLine("|$($DescLine.PadRight(78))|")
                }
            }

            [void]$Builder.AppendLine("+------------------------------------------------------------------------------+")
            [void]$Builder.AppendLine("")

            if ($PrimaryAttackRisks.Count -gt 0) {
                [void]$Builder.AppendLine("    PRIMARY ATTACK RISKS")
                [void]$Builder.AppendLine("  ───────────────────────")

                $Index = 0
                $Last = $PrimaryAttackRisks.Count

                foreach ($Node in $PrimaryAttackRisks) {
                    $Index++
                    $Prefix = "├──"
                    if ($Index -eq $Last) { $Prefix = "└──" }

                    $EntityText = ""
                    if ($Node.Entity) { $EntityText = " [Target: $($Node.Entity)]" }

                    $FullNodeText = "$Prefix [$($Node.Severity.ToUpper())] $($Node.Title)$EntityText"
                    $WrappedNodeLines = Format-WFLWrappedLines -Text $FullNodeText -MaxWidth 72

                    $NIdx = 0
                    foreach ($WLine in $WrappedNodeLines) {
                        if ($NIdx -eq 0) {
                            [void]$Builder.AppendLine("   $WLine")
                        } else {
                            [void]$Builder.AppendLine("       $WLine")
                        }
                        $NIdx++
                    }
                }
                [void]$Builder.AppendLine("")
            }

            if ($ContributingConditions.Count -gt 0) {
                [void]$Builder.AppendLine("     CONTRIBUTING CONDITIONS")
                [void]$Builder.AppendLine("  ───────────────────────────")

                $Index = 0
                $Last = $ContributingConditions.Count

                foreach ($Node in $ContributingConditions) {
                    $Index++
                    $Prefix = "├──"
                    if ($Index -eq $Last) { $Prefix = "└──" }

                    $EntityText = ""
                    if ($Node.Entity) { $EntityText = " [Target: $($Node.Entity)]" }

                    $FullNodeText = "$Prefix [$($Node.Severity.ToUpper())] $($Node.Title)$EntityText"
                    $WrappedNodeLines = Format-WFLWrappedLines -Text $FullNodeText -MaxWidth 72

                    $NIdx = 0
                    foreach ($WLine in $WrappedNodeLines) {
                        if ($NIdx -eq 0) {
                            [void]$Builder.AppendLine("   $WLine")
                        } else {
                            [void]$Builder.AppendLine("       $WLine")
                        }
                        $NIdx++
                    }
                }
                [void]$Builder.AppendLine("")
            }

            [void]$Builder.AppendLine("    RECOMMENDED ACTION")
            [void]$Builder.AppendLine("  ─────────────────────")
            
            $RecActionText = Get-WFLRecommendedAction -Impact $Impact -Nodes $ImpactNodes
            $WrappedRecLines = Format-WFLWrappedLines -Text $RecActionText -MaxWidth 72
            foreach ($RLine in $WrappedRecLines) {
                [void]$Builder.AppendLine("   $RLine")
            }
            [void]$Builder.AppendLine("")
            [void]$Builder.AppendLine("--------------------------------------------------------------------------------")
            [void]$Builder.AppendLine("")
        }

        if ($ScenarioCount -eq 0) {
            [void]$Builder.AppendLine(" [+] No impact-based attack paths matched the current actionable telemetry.")
            [void]$Builder.AppendLine("")
        }

        Write-WFLAttackOutput $Builder.ToString()
    }
    catch {
        $ErrorText = $_ | Format-List * -Force | Out-String
        Write-WFLAttackOutput $ErrorText
    }
}
