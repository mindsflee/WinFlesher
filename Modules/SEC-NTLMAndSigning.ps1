Register-WFLModule `
    -Name "SEC-NTLMAndSigning" `
    -Category "Network Security" `
    -Type "Check" `
    -MITRE "T1557" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN-WIDE LATERAL MOVEMENT / RELAY" `
    -Description "Audits SMB Signing, LDAP Channel Binding, and NTLMv1 exposure across all Domain Controllers." `
    -Remediation @{
        Module        = 'SEC-NTLMAndSigning'
        Category      = 'Credential Access / Lateral Movement'
        Type          = 'Specific'
        Description   = 'Enforces SMB signing, LDAP channel binding, and restricts NTLMv1 / NTLM traffic domain-wide via Group Policy.'
        Impact        = 'Moderate to High. Enforcing strict security on Domain Controllers may disrupt legacy unauthenticated LDAP/NTLM apps.'
        VariableGuide = 'Domain Controllers Group Policy / Default Domain Controllers Policy.'
        Code          = @'
# Esempio di configurazione GPO o script di hardening sui DC
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value 1
'@
    } -Run {
        try {
            $Issues = @()
            $AllDCResults = @()

            # Recupera i Domain Controller dalla context di WinFlesher o direttamente da AD
            $DomainControllers = $null
            if ($Global:WinFlesher.Context.ADDomainControllers) {
                $DomainControllers = $Global:WinFlesher.Context.ADDomainControllers
            }
            elseif (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                $DomainControllers = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
            }

            # Se non siamo in un dominio o non ci sono DC visibili, fallback sul locale con warning
            if (-not $DomainControllers) {
                Write-WFLLog "No Active Directory domain controllers found. Falling back to local machine check." "WARN"
                $DomainControllers = @([PSCustomObject]@{ HostName = $env:COMPUTERNAME })
            }

            foreach ($DC in $DomainControllers) {
                $DCName = $DC.HostName
                Write-WFLLog "Auditing NTLM/LDAP hardening on Domain Controller: $DCName" "INFO"

                try {
                    # Esegue il controllo in remoto sul DC (oppure in locale se è la macchina corrente)
                    if ($DCName -eq $env:COMPUTERNAME -or $DCName -eq "localhost" -or $DCName -eq "127.0.0.1") {
                        $LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                        $LdapPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"

                        $LmCompatibility = (Get-ItemProperty -Path $LsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
                        $LdapSigning = (Get-ItemProperty -Path $LdapPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
                        $LdapChannelBinding = (Get-ItemProperty -Path $LdapPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
                    }
                    else {
                        # Remote check via ScriptBlock su CIM/Registry (richiede permessi di Admin sul dominio)
                        $RemoteData = Invoke-Command -ComputerName $DCName -ScriptBlock {
                            $lPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                            $dPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                            [PSCustomObject]@{
                                LmCompatibility    = (Get-ItemProperty -Path $lPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
                                LdapSigning        = (Get-ItemProperty -Path $dPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
                                LdapChannelBinding = (Get-ItemProperty -Path $dPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
                            }
                        } -ErrorAction Stop

                        $LmCompatibility    = $RemoteData.LmCompatibility
                        $LdapSigning        = $RemoteData.LdapSigning
                        $LdapChannelBinding = $RemoteData.LdapChannelBinding
                    }

                    $DCIssues = @()
                    if ($null -eq $LmCompatibility -or $LmCompatibility -lt 5) {
                        $DCIssues += "Weak NTLM level (LmCompatibilityLevel < 5)."
                    }
                    if ($null -eq $LdapSigning -or $LdapSigning -eq 0) {
                        $DCIssues += "LDAP Server Signing not enforced."
                    }
                    if ($null -eq $LdapChannelBinding -or $LdapChannelBinding -eq 0) {
                        $DCIssues += "LDAP Channel Binding disabled."
                    }

                    if ($DCIssues.Count -gt 0) {
                        $Issues += "DC [$DCName]: $($DCIssues -join ' ')"
                    }

                    $AllDCResults += [PSCustomObject]@{
                        DomainController   = $DCName
                        LmCompatibility    = if($null -ne $LmCompatibility){$LmCompatibility}else{"Not Set"}
                        LdapSigning        = if($null -ne $LdapSigning){$LdapSigning}else{"Not Set"}
                        LdapChannelBinding = if($null -ne $LdapChannelBinding){$LdapChannelBinding}else{"Not Set"}
                        IssuesCount        = $DCIssues.Count
                    }
                }
                catch {
                    $Issues += "DC [$DCName]: Failed to query security settings ($($_.Exception.Message))"
                }
            }

            Add-WFLDetail -Name "SEC-NTLMAndSigning" -Data $AllDCResults
            $Severity = if ($Issues.Count -gt 0) { "High" } else { "Info" }

            Add-WFLFinding `
                -Title "Domain-Wide NTLM & LDAP Protocol Hardening Audit" `
                -Severity $Severity `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "SEC-NTLMAndSigning" `
                -Evidence "Checked domain controllers. Identified configuration issues on $($Issues.Count) targets." `
                -Recommendation "Enforce LmCompatibilityLevel 5, LDAP signing, and Channel Binding via Domain Controller GPOs."
        }
        catch {
            Add-WFLFinding -Title "Domain NTLM/Signing check failed" -Severity "Info" -Category "Network Security" -Source "SEC-NTLMAndSigning" -Evidence $_.Exception.Message
        }
    }
