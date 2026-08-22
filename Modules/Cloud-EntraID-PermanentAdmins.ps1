Register-WFLModule `
    -Name "Cloud-EntraID-PermanentAdmins" `
    -Category "Cloud / Hybrid Identity" `
    -Type "Check" `
    -MITRE "T1078.004" `
    -Tactic "Privilege Escalation" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Identifies accounts holding permanent Tier-0 global roles in Entra ID without requiring Privileged Identity Management (PIM) activation." `
        -Remediation @{
        Module        = 'Cloud-EntraID-PermanentAdmins'
        Category      = 'Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Migrates permanent global and privileged role assignments in Entra ID to eligible assignments managed via Privileged Identity Management (PIM).'
        Impact        = 'Moderate. Enhances cloud administrative security posture.'
        VariableGuide = 'User principal names holding permanent tenant roles.'
        Code          = @'
Connect-MgGraph; # Convert permanent role assignment to PIM eligible assignment.
'@
    } -Run {

        $Cloud = $Global:WinFlesher.Context.EntraID

        if (-not $Cloud.Available) {

            Add-WFLFinding `
                -Title "Permanent privileged roles review unavailable" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -Source "Cloud-EntraID-PermanentAdmins"

            return
        }

        $Admins = @($Global:WinFlesher.Context.EntraIDPermanentAdmins)

        Add-WFLDetail `
            -Name "Cloud-EntraID-PermanentAdmins" `
            -Data $Admins

        if($Admins.Count -eq 0)
        {
            Add-WFLFinding `
                -Title "Permanent administrators review passed" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -Source "Cloud-EntraID-PermanentAdmins" `
                -Evidence "No permanent cloud administrative accounts found outside PIM."

            return
        }

        $GlobalAdmins = @(
            $Admins | Where-Object {
                $_.RoleName -eq "Global Administrator" -and $_.IsPIMManaged -eq $false
            }
        )

        $Severity = "Medium"

        if($Admins.Count -gt 3)
        {
            $Severity = "High"
        }

        if($GlobalAdmins.Count -gt 0)
        {
            $Severity = "Critical"
        }

        Add-WFLFinding `
            -Title "Permanent privileged cloud accounts audit" `
            -Severity $Severity `
            -Category "Cloud / Hybrid Identity" `
            -MITRE "T1078.004" `
            -Tactic "Privilege Escalation" `
            -Source "Cloud-EntraID-PermanentAdmins" `
            -Evidence "TotalPermanentAdmins=$($Admins.Count); PermanentGlobalAdmins=$($GlobalAdmins.Count)" `
            -Recommendation "Migrate permanent privileged cloud roles to eligible assignments managed via Microsoft Entra Privileged Identity Management (PIM)."
    }


