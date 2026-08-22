Register-WFLModule `
    -Name "AD-BackupOperators-Abuse" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1078" `
    -Tactic "Privilege Escalation / Persistence" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Reviews membership of Backup Operators and related sensitive groups for potential escalation risks." `
        -Remediation @{
        Module        = 'AD-BackupOperators-Abuse'
        Category      = 'Privilege Escalation / Persistence'
        Type          = 'Specific'
        Description   = 'Reviews and purges unauthorized or excessive memberships inside the Backup Operators and related sensitive default groups.'
        Impact        = 'Moderate. Restricting group membership prevents lateral movement and privilege escalation, but ensure legitimate backup service accounts retain required permissions.'
        VariableGuide = '$GroupName: Name of the target privileged group (default: "Backup Operators").'
        Code          = @'
Get-ADGroupMember -Identity "Backup Operators" | Remove-ADGroupMember -Identity "Backup Operators" -Confirm:$false
'@
    } -Run {

        $AD = $Global:WinFlesher.Context.ActiveDirectory

        if (-not $AD.Available) {

            Add-WFLFinding `
                -Title "Backup Operators review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-BackupOperators-Abuse"

            return
        }

        $BackupOperators = @()
        try {
            $GroupMembers = Get-ADGroupMember -Identity "Backup Operators" -ErrorAction SilentlyContinue
            foreach ($member in $GroupMembers) {
                if ($member.objectClass -eq "user") {
                    $userDetails = Get-ADUser -Identity $member.DistinguishedName -Properties AdminCount, Enabled -ErrorAction SilentlyContinue
                    if ($userDetails) {
                        $BackupOperators += [PSCustomObject]@{
                            Name                  = $userDetails.Name
                            SamAccountName        = $userDetails.SamAccountName
                            Enabled               = $userDetails.Enabled
                            AdminCount            = if ($userDetails.AdminCount -eq 1) { 1 } else { 0 }
                            DistinguishedName     = $userDetails.DistinguishedName
                        }
                    }
                } else {
                    $BackupOperators += [PSCustomObject]@{
                        Name                  = $member.Name
                        SamAccountName        = $member.sAMAccountName
                        Enabled               = $true
                        AdminCount            = 0
                        DistinguishedName     = $member.DistinguishedName
                    }
                }
            }
        }
        catch {
            $BackupOperators = @($Global:WinFlesher.Context.ADBackupOperators)
        }

        Add-WFLDetail `
            -Name "AD-BackupOperators-Abuse" `
            -Data $BackupOperators

        if($BackupOperators.Count -eq 0)
        {
            Add-WFLFinding `
                -Title "Backup Operators review passed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-BackupOperators-Abuse" `
                -Evidence "No members found in Backup Operators group."

            return
        }

        $Privileged = @(
            $BackupOperators | Where-Object { $_.AdminCount -eq 1 }
        )

        $EnabledMembers = @(
            $BackupOperators | Where-Object { $_.Enabled -eq $true }
        )

        $Severity = "Low"

        if($BackupOperators.Count -gt 2)
        {
            $Severity = "Medium"
        }

        if($Privileged.Count -gt 0 -or $EnabledMembers.Count -gt 5)
        {
            $Severity = "High"
        }

        Add-WFLFinding `
            -Title "Backup Operators membership exposure review" `
            -Severity $Severity `
            -Category "Active Directory" `
            -MITRE "T1078" `
            -Tactic "Privilege Escalation / Persistence" `
            -Source "AD-BackupOperators-Abuse" `
            -Evidence "TotalMembers=$($BackupOperators.Count); EnabledMembers=$($EnabledMembers.Count); PrivilegedMembers=$($Privileged.Count)" `
            -Recommendation "Restrict membership in the Backup Operators group to authorized maintenance accounts only, as members can read sensitive files and compromise domain data."
    }


