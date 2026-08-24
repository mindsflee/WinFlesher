Register-WFLModule `
    -Name "Security-APT-ShadowCredentials" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1556.001, T1098" `
    -Tactic "Credential Access, Persistence" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Detects active usage and potential exploitation of Shadow Credentials (msDS-KeyCredentialLink attribute)." `
        -Remediation @{
        Module        = 'Security-APT-ShadowCredentials'
        Category      = 'Credential Access / Persistence'
        Type          = 'Specific'
        Description   = 'Detects and purges unauthorized public key certificates bound to the msDS-KeyCredentialLink attribute used in Shadow Credentials attacks.'
        Impact        = 'Low. Revokes unauthorized key credentials mapped to high-value accounts.'
        VariableGuide = '$Identity: Target user or computer object.'
        Code          = @'
Set-ADUser -Identity "TargetUser" -Clear "msDS-KeyCredentialLink"
'@
    } -Run {
        Write-Verbose "Executing Shadow Credentials (msDS-KeyCredentialLink) audit..."

        $Issues = @()
        $ShadowCredentialTargets = @()

        try {
            $filter = "(msDS-KeyCredentialLink=*)"
            
            $searcher = [ADSISearcher]$filter
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "distinguishedName", "objectClass", "msDS-KeyCredentialLink", "whenModified")) | Out-Null

            $results = $searcher.FindAll()

            if ($results.Count -gt 0) {
                Write-Verbose "Found $($results.Count) object(s) with populated msDS-KeyCredentialLink attributes."

                foreach ($res in $results) {
                    $account = $res.Properties["samaccountname"][0]
                    $dn = $res.Properties["distinguishedname"][0]
                    $modified = $res.Properties["whenmodified"][0]
                    $keyCount = $res.Properties["msds-keycredentiallink"].Count

                    $ShadowCredentialTargets += [PSCustomObject]@{
                        sAMAccountName = $account
                        DN             = $dn
                        KeyCount       = $keyCount
                        LastModified   = $modified
                    }

                    Write-Verbose "Shadow Credential detected on account '$account' ($keyCount key(s) linked)."
                    $Issues += "Shadow Credential key detected on account '$account' (DN: $dn)"
                }
            } else {
                Write-Verbose "No objects found with populated msDS-KeyCredentialLink attributes."
            }
        }
        catch {
            Write-Verbose "Failed to search Active Directory for msDS-KeyCredentialLink. Ensure execution in a Domain context: $_"
            Add-WFLFinding `
                -Title "Shadow Credentials check unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1556.001" `
                -Tactic "Persistence" `
                -Source "Security-APT-ShadowCredentials" `
                -Evidence "Unable to query AD via ADSI/LDAP: $($_.Exception.Message)" `
                -Recommendation "Verify domain connectivity and LDAP privileges."
            return
        }

        Add-WFLDetail -Name "Security-APT-ShadowCredentials" -Data $ShadowCredentialTargets

 if ($Issues.Count -gt 0) {
    Write-Verbose "Shadow Credentials persistence identified on domain objects."


    $Global:WinFlesher.Details["Security-APT-ShadowCredentials"] = $Issues

    Add-WFLFinding `
        -Title "Active Shadow Credentials (msDS-KeyCredentialLink) detected" `
        -Severity "High" `
        -Category "Active Directory" `
        -MITRE "T1556.001, T1098" `
        -Tactic "Credential Access, Persistence" `
        -Source "Security-APT-ShadowCredentials" `
        -Evidence "$($Issues.Count) account(s) detected with msDS-KeyCredentialLink attribute populated." `
        -Recommendation "Verify whether Windows Hello for Business (WHfB) or FIDO2 keys are legitimately deployed. If WHfB is not used, clear the msDS-KeyCredentialLink attribute on flagged objects and inspect ACLs on the target accounts for unexpected WriteProperty rights."
}
else {
    Write-Verbose "Shadow Credentials check completed. No suspicious KeyCredentialLink attributes found."
    Add-WFLFinding `
        -Title "Shadow Credentials review passed" `
        -Severity "Info" `
        -Category "Active Directory" `
        -MITRE "T1556.001, T1098" `
        -Tactic "Persistence" `
        -Source "Security-APT-ShadowCredentials" `
        -Evidence "No domain objects currently possess msDS-KeyCredentialLink attributes." `
        -Recommendation "Monitor Active Directory Directory Service event logs (Event ID 5136) for modifications to the msDS-KeyCredentialLink attribute."
}
    }


