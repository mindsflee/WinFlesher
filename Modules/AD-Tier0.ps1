Register-WFLModule `
    -Name "AD-Tier0-Review" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1069.002" `
    -Tactic "Discovery" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Reviews Tier-0 privileged memberships." `
-Remediation @{
        Module        = 'AD-Tier0.ps1'
        Category      = 'Active Directory Security'
        Type          = 'Specific'
        Description   = 'Segregate and protect Tier 0 assets by disabling Domain Admin credential caching.'
        Impact        = 'Prevents hash and Kerberos ticket theft from less secure workstations.'
        VariableGuide = 'No variables required for local registry hardening.'
        Code          = @'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0
Write-Host "[+] Credential caching disabled to prevent ticket/hash theft." -ForegroundColor Green
'@
    } -Run {

        $AD = $Global:WinFlesher.Context.ActiveDirectory

        if (-not $AD.Available) {

            Add-WFLFinding `
                -Title "Tier-0 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-Tier0-Review"

            return
        }

        $Members = @(
            $Global:WinFlesher.Context.ADPrivilegedGroupMembers
        )

        $Tier0 = @(
            $Members | Where-Object {
                $_.Group -in @(
                    "Domain Admins",
                    "Enterprise Admins",
                    "Schema Admins"
                )
            }
        )

        Add-WFLDetail `
            -Name "AD-Tier0" `
            -Data $Tier0

        $Count = $Tier0.Count

        $UniqueAccounts = @(
            $Tier0 |
            Select-Object SamAccountName -Unique
        ).Count

        $Severity = "Info"

        if($UniqueAccounts -gt 5)
        {
            $Severity = "Low"
        }

        if($UniqueAccounts -gt 15)
        {
            $Severity = "Medium"
        }

        if($UniqueAccounts -gt 30)
        {
            $Severity = "High"
        }

        Add-WFLFinding `
            -Title "Tier-0 privilege review" `
            -Severity $Severity `
            -Category "Active Directory" `
            -MITRE "T1069.002" `
            -Tactic "Discovery" `
            -Source "AD-Tier0-Review" `
            -Evidence "Tier0Members=$Count; UniqueTier0Accounts=$UniqueAccounts" `
            -Recommendation "Review Tier-0 assignments and ensure administrative accounts are separated from daily-use accounts."
    }


