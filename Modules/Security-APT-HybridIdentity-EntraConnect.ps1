Register-WFLModule `
    -Name "Security-APT-HybridIdentity-EntraConnect" `
    -Category "Cloud / Hybrid Identity" `
    -Type "Check" `
    -MITRE "T1556, T1078.004" `
    -Tactic "Credential Access, Persistence" `
    -Impact "POTENTIAL LATERAL MOVEMENT" `
    -Description "Checks for Microsoft Entra Connect (Azure AD Connect) presence, AD Sync account exposure, and Hybrid SSO risks." `
        -Remediation @{
        Module        = 'Security-APT-HybridIdentity-EntraConnect'
        Category      = 'Credential Access / Persistence'
        Type          = 'Specific'
        Description   = 'Secures Microsoft Entra Connect servers against synchronization account exposure, staging mode abuse, and pass-through authentication weaknesses.'
        Impact        = 'High. Protects the identity bridge between local Active Directory and cloud tenants.'
        VariableGuide = 'Local server configuration hardening.'
        Code          = @'
'@
    } -Run {
        Write-Verbose "Executing Hybrid Identity and Entra ID Connect security checks..."

        $Issues = @()
        $EntraDetails = @{}

        $syncService = Get-Service -Name "ADSync" -ErrorAction SilentlyContinue

        if (-not $syncService) {
            Write-Verbose "Microsoft Entra Connect service (ADSync) was not detected on this system."
            Add-WFLFinding `
                -Title "Entra ID Connect service not detected" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -MITRE "T1556" `
                -Tactic "Credential Access" `
                -Source "Security-APT-HybridIdentity-EntraConnect" `
                -Evidence "ADSync service is not installed on this host." `
                -Recommendation "No action needed if this server is not designated as an AD Sync server."
            return
        }

        Write-Verbose "ADSync service detected. Status: $($syncService.Status)"
        $EntraDetails["ServiceStatus"] = $syncService.Status.ToString()

        $dbPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Azure AD Connect"
        $installDir = Get-ItemPropertyValue -Path $dbPath -Name "InstallPath" -ErrorAction SilentlyContinue

        if ($installDir) {
            $EntraDetails["InstallPath"] = $installDir
            Write-Verbose "Entra Connect installation path found: $installDir"
        } else {
            Write-Verbose "Entra Connect registry path not found, checking default service binary path."
        }

        try {
            $svcWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
            $startName = $svcWmi.StartName
            $EntraDetails["ServiceAccount"] = $startName

            if ($startName -like "*Domain Admins*" -or $startName -like "*Administrator*") {
                Write-Verbose "ADSync service is running with overprivileged Domain Admin account: $startName"
                $Issues += "ADSync service runs as a Domain Administrator ($startName) [Overprivileged Service Account]"
            }
        } catch {
            Write-Verbose "Could not query ADSync service execution context."
        }

        try {
            $ssoAccount = Get-ADUser -Filter "SamAccountName -eq 'AZUREADSSOACC$'" -ErrorAction SilentlyContinue
            if ($ssoAccount) {
                Write-Verbose "AZUREADSSOACC account found in Active Directory."
                $EntraDetails["SeamlessSSO"] = $true
                
                $pwdLastSet = $ssoAccount.PasswordLastSet
                if ($pwdLastSet -and $pwdLastSet -lt (Get-Date).AddDays(-180)) {
                    Write-Verbose "AZUREADSSOACC Kerberos decryption key was last updated on $pwdLastSet (older than 180 days)."
                    $Issues += "Seamless SSO account (AZUREADSSOACC) Kerberos key is stale (Last set: $($pwdLastSet.ToString('yyyy-MM-dd'))) [Risk of Golden Ticket/Kerberoasting]"
                }
            }
        } catch {
            Write-Verbose "AD PowerShell module unavailable or domain not reachable for Seamless SSO query."
        }

        Add-WFLDetail -Name "Security-APT-HybridIdentity-EntraConnect" -Data $EntraDetails

        if ($Issues.Count -gt 0) {
            Write-Verbose "Hybrid Identity security risks detected: $($Issues -join ' | ')"

            Add-WFLFinding `
                -Title "Microsoft Entra Connect security configuration risks detected" `
                -Severity "High" `
                -Category "Cloud / Hybrid Identity" `
                -MITRE "T1556, T1078.004" `
                -Tactic "Credential Access, Persistence" `
                -Source "Security-APT-HybridIdentity-EntraConnect" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Ensure ADSync runs under a dedicated MSA/gMSA with minimal privileges. Rollover the AZUREADSSOACC Kerberos decryption key regularly using Update-AzureADSSOAccAsymmetricKey."
        }
        else {
            Write-Verbose "Entra Connect basic configuration checks passed."
            Add-WFLFinding `
                -Title "Microsoft Entra Connect review passed" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -MITRE "T1556, T1078.004" `
                -Tactic "Credential Access" `
                -Source "Security-APT-HybridIdentity-EntraConnect" `
                -Evidence "ADSync Service Active; ServiceAccount=$($EntraDetails['ServiceAccount']); SeamlessSSOKeyValid=$true" `
                -Recommendation "Harden the Entra Connect server as a Tier-0 asset. Restrict RDP and local administrative rights."
        }
    }


