Register-WFLModule `
    -Name "Cloud-EntraID-OAuthConsents" `
    -Category "Cloud / Hybrid Identity" `
    -Type "Check" `
    -MITRE "T1528, T1098" `
    -Tactic "Persistence / Defense Evasion" `
    -Impact "POTENTIAL PERSISTENCE" `
    -Description "Audits user and admin consent grants for enterprise applications to detect illicit app consent abuse and unauthorized API access." `
        -Remediation @{
        Module        = 'Cloud-EntraID-OAuthConsents'
        Category      = 'Persistence / Defense Evasion'
        Type          = 'Specific'
        Description   = 'Revokes illicit or unauthorized user and administrator OAuth consent grants assigned to third-party enterprise applications.'
        Impact        = 'Low. Terminates unauthorized third-party application API access tokens.'
        VariableGuide = '$ServicePrincipalId: Unauthorized application service principal identifier.'
        Code          = @'
Connect-MgGraph; Remove-MgServicePrincipal -ServicePrincipalId <ID>
'@
    } -Run {

        $Cloud = $Global:WinFlesher.Context.EntraID

        if (-not $Cloud.Available) {

            Add-WFLFinding `
                -Title "Entra ID OAuth consents review unavailable" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -Source "Cloud-EntraID-OAuthConsents"

            return
        }

        $Consents = @($Global:WinFlesher.Context.EntraIDOAuthConsents)

        Add-WFLDetail `
            -Name "Cloud-EntraID-OAuthConsents" `
            -Data $Consents

        if($Consents.Count -eq 0)
        {
            Add-WFLFinding `
                -Title "OAuth consents review passed" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -Source "Cloud-EntraID-OAuthConsents" `
                -Evidence "No risky or unusual OAuth app consents found."

            return
        }

        $HighPrivilegeConsents = @(
            $Consents | Where-Object {
                $_.HasHighPrivilegePermissions -eq $true -or $_.ConsentType -eq "All"
            }
        )

        $Severity = "Low"

        if($Consents.Count -gt 5)
        {
            $Severity = "Medium"
        }

        if($HighPrivilegeConsents.Count -gt 0)
        {
            $Severity = "High"
        }

        Add-WFLFinding `
            -Title "Enterprise applications OAuth consent exposure" `
            -Severity $Severity `
            -Category "Cloud / Hybrid Identity" `
            -MITRE "T1528, T1098" `
            -Tactic "Persistence / Defense Evasion" `
            -Source "Cloud-EntraID-OAuthConsents" `
            -Evidence "TotalConsents=$($Consents.Count); HighPrivilegeConsents=$($HighPrivilegeConsents.Count)" `
            -Recommendation "Review application permissions and user consent settings in Microsoft Entra ID to restrict unauthorized API access."
    }


