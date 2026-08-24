Register-WFLModule `
    -Name "AD-KRBTGT-Hygiene" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1558" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL PERSISTENCE" `
    -Description "Reviews KRBTGT password age and rotation health." `
        -Remediation @{
        Module        = 'AD-KRBTGT-Hygiene'
        Category      = 'Credential Access / Persistence'
        Type          = 'Specific'
        Description   = 'Performs the mandatory double-rotation cycle of the krbtgt account password to invalidate active Golden Tickets.'
        Impact        = 'High. Invalidates all active Kerberos tickets domain-wide, requiring services and user sessions to re-authenticate.'
        VariableGuide = 'Ensure a minimum time delta between the first and second krbtgt password reset.'
        Code          = @'
Reset-ADKrbtgtAccountPassword -Identity krbtgt
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "KRBTGT review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-KRBTGT-Hygiene" `
                -Evidence "AD unavailable."
            return
        }

        try {
            $KRBTGT = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, Created -ErrorAction Stop

            if ($null -eq $KRBTGT.PasswordLastSet) {
                $Age = (New-TimeSpan -Start $KRBTGT.Created -End (Get-Date)).Days
            } else {
                $Age = (New-TimeSpan -Start $KRBTGT.PasswordLastSet -End (Get-Date)).Days
            }

            Add-WFLDetail -Name "AD-KRBTGT" -Data $KRBTGT

            $Severity = "Info"
            if ($Age -gt 1095) { $Severity = "Medium" }
            if ($Age -gt 1825) { $Severity = "High" }
            if ($Age -gt 3650) { $Severity = "Critical" }

            Add-WFLFinding `
                -Title "KRBTGT password hygiene review" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1558" `
                -Tactic "Credential Access" `
                -Source "AD-KRBTGT-Hygiene" `
                -Evidence "PasswordAgeDays=$Age; PasswordLastSet=$($KRBTGT.PasswordLastSet)" `
                -Recommendation "Rotate KRBTGT password twice in succession (allowing replication time between rotations) according to security baseline."
        }
        catch {
            Add-WFLFinding `
                -Title "KRBTGT review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-KRBTGT-Hygiene" `
                -Evidence $_.Exception.Message
        }
    }


