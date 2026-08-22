Register-WFLModule `
    -Name "AD-Privileged-Groups" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1069.002" `
    -Tactic "Discovery" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Summarizes membership of common privileged Active Directory groups." `
  -Remediation @{
        Module        = 'AD-Privileged-Groups.ps1'
        Category      = 'Active Directory Security'
        Type          = 'Specific'
        Description   = 'Remove unauthorized accounts from high-privilege Active Directory groups (e.g., Domain Admins).'
        Impact        = 'Reduces tier-0 attack surface by blocking persistence from unverified users in critical groups.'
        VariableGuide = 'Replace [Rogue_Username] with the account detected by the module.'
        Code          = @'
$groupName = "Domain Admins"
$rogueUser = "[Rogue_Username]"
Remove-ADGroupMember -Identity $groupName -Members $rogueUser -Confirm:$false
Write-Host "[!] User $rogueUser successfully removed from $groupName." -ForegroundColor Yellow
'@
    } -Run {
        $AD = $Global:WinFlesher.Context.ActiveDirectory

        if (-not $AD -or $AD.Available -ne $true) {
            Add-WFLFinding `
                -Title "Active Directory privileged group review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1069.002" `
                -Tactic "Discovery" `
                -Source "AD-Privileged-Groups" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module if AD checks are required."
            return
        }

        $Members = @($Global:WinFlesher.Context.ADPrivilegedGroupMembers)

        Add-WFLDetail -Name "AD-Privileged-Groups" -Data $Members

        if ($Members.Count -eq 0) {
            Add-WFLFinding `
                -Title "No privileged AD group members collected" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1069.002" `
                -Tactic "Discovery" `
                -Source "AD-Privileged-Groups" `
                -Evidence "ADPrivilegedGroupMembers is empty." `
                -Recommendation "Verify permissions and group names if this result is unexpected."
            return
        }

        $GroupSummary = $Members |
            Group-Object Group |
            ForEach-Object {
                "{0}={1}" -f $_.Name, $_.Count
            }

        $SensitiveCount = @($Members | Where-Object {
            $_.Group -in @("Domain Admins","Enterprise Admins","Schema Admins")
        }).Count

        $Severity = "Info"

        if ($SensitiveCount -gt 0) {
            $Severity = "Medium"
        }

        Add-WFLFinding `
            -Title "Privileged AD group membership review" `
            -Severity $Severity `
            -Category "Active Directory" `
            -MITRE "T1069.002" `
            -Tactic "Discovery" `
            -Source "AD-Privileged-Groups" `
            -Evidence "TotalEntries=$($Members.Count); SensitiveGroupEntries=$SensitiveCount; $($GroupSummary -join '; ')" `
            -Recommendation "Review privileged group membership, remove stale accounts, and apply tiered administration. Use Show-WFLDetails -Name AD-Privileged-Groups for details."
    }



