Register-WFLModule `
    -Name "ADCS-ESC11" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Checks whether AD CS RPC enrollment enforces encrypted certificate requests (ESC11)." `
        -Remediation @{
        Module        = 'ADCS-ESC11'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Enforces RPC encryption and mutual authentication on AD CS enrollment endpoints to mitigate ESC11 coercion and relay attacks.'
        Impact        = 'Low. Secures certificate enrollment interfaces.'
        VariableGuide = 'Registry configuration on Certification Authority servers.'
        Code          = @'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\Parameters" -Name "RPCEncryptRequestSignature" -Value 1
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "ADCS ESC11 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC11" `
                -Evidence "Active Directory discovery unavailable."
            return
        }

        try {
            $ConfigNC = (Get-ADRootDSE).configurationNamingContext
            $CAPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"

            $CAs = @(Get-ADObject `
                -SearchBase $CAPath `
                -LDAPFilter "(objectClass=pKIEnrollmentService)" `
                -Properties cn,dNSHostName `
                -ErrorAction Stop)

            $Results = @()

            foreach ($CA in $CAs) {
                $CAName = [string]$CA.cn
                $HostName = [string]$CA.dNSHostName

                if ([string]::IsNullOrWhiteSpace($HostName)) { continue }

                $CertutilOutput = ""
                $EnforceEncryption = $null
                $QuerySucceeded = $false

                try {
                    $CertutilOutput = certutil.exe -config "$HostName\$CAName" -getreg CA\InterfaceFlags 2>&1 | Out-String
                    $QuerySucceeded = $true

                    if ($CertutilOutput -match "IF_ENFORCEENCRYPTICERTREQUEST" -or $CertutilOutput -match "300") {
                        $EnforceEncryption = $true
                    }
                    elseif ($CertutilOutput -match "InterfaceFlags") {
                        $EnforceEncryption = $false
                    }
                }
                catch {
                    $CertutilOutput = $_.Exception.Message
                }

                $Results += [PSCustomObject]@{
                    CAName                   = $CAName
                    DNSHostName              = $HostName
                    QuerySucceeded           = $QuerySucceeded
                    EnforceEncryptedRequests = $EnforceEncryption
                    RawEvidence              = ($CertutilOutput -replace "`r|`n", " ")
                }
            }

            Add-WFLDetail -Name "ADCS-ESC11" -Data $Results

            $Unknown     = @($Results | Where-Object { $null -eq $_.EnforceEncryptedRequests })
            $NotEnforced = @($Results | Where-Object { $_.EnforceEncryptedRequests -eq $false })
            $Enforced    = @($Results | Where-Object { $_.EnforceEncryptedRequests -eq $true })

            $Severity = "Info"
            if ($Unknown.Count -gt 0)     { $Severity = "Low" }
            if ($NotEnforced.Count -gt 0)  { $Severity = "High" }

            Add-WFLFinding `
                -Title "AD CS ESC11 RPC enrollment encryption review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC11" `
                -Evidence "EncryptedRequestEnforced=$($Enforced.Count); NotEnforced=$($NotEnforced.Count); Unknown=$($Unknown.Count); CheckedCAs=$($Results.Count)" `
                -Recommendation "Set IF_ENFORCEENCRYPTICERTREQUEST flag on CAs using 'certutil -setreg CA\InterfaceFlags +0x300' and restart Certificate Services."
        }
        catch {
            Add-WFLFinding `
                -Title "AD CS ESC11 review failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC11" `
                -Evidence $_.Exception.Message
        }
    }


