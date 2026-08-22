Register-WFLModule `
    -Name "ADCS-ESC6" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews Enterprise CA configuration for EDITF_ATTRIBUTESUBJECTALTNAME2 SAN risk exposure (ESC6)." `
        -Remediation @{
        Module        = 'ADCS-ESC6'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Disables the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on Enterprise Certification Authorities to prevent unauthorized Subject Alternative Name injection.'
        Impact        = 'Moderate. Prevents users from requesting certificates for arbitrary accounts (including Domain Admins) via SAN manipulation.'
        VariableGuide = 'CA Server configuration flag.'
        Code          = @'
certutil.exe -setreg CA\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding -Title "AD CS ESC6 review unavailable" -Severity "Info" -Category "Active Directory Certificate Services" -Source "ADCS-ESC6" -Evidence "AD unavailable."
            return
        }

        try {
            $ConfigNC = (Get-ADRootDSE).configurationNamingContext
            $CAs = Get-ADObject `
                -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC" `
                -LDAPFilter "(objectClass=pKIEnrollmentService)" `
                -Properties cn, dNSHostName, flags, msPKI-Enrollment-Flag -ErrorAction Stop

            $Results = @()
            $VulnerableCAs = 0

            foreach ($CA in $CAs) {
                $CAName = $CA.cn
                $HostName = $CA.dNSHostName
                $IsVulnerable = $false
                $CheckMethod = "LDAP Attribute Check"

                try {
                    $CertutilOutput = certutil.exe -config "$HostName\$CAName" -getreg policy\EditFlags 2>&1 | Out-String
                    if ($CertutilOutput -match "EDITF_ATTRIBUTESUBJECTALTNAME2") {
                        $IsVulnerable = $true
                        $CheckMethod = "RPC/Registry Query"
                    }
                }
                catch {
                    if ($CA.flags -and ($CA.flags -band 0x00040000)) {
                        $IsVulnerable = $true
                    }
                }

                if ($IsVulnerable) { $VulnerableCAs++ }

                $Results += [PSCustomObject]@{
                    CAName       = $CAName
                    DNSHostName  = $HostName
                    SAN2Enabled  = $IsVulnerable
                    AuditMethod  = $CheckMethod
                }
            }

            Add-WFLDetail -Name "ADCS-ESC6" -Data $Results

            $Severity = if ($VulnerableCAs -gt 0) { "High" } else { "Info" }

            Add-WFLFinding `
                -Title "AD CS ESC6 SAN Configuration Review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC6" `
                -Evidence "CheckedCAs=$($CAs.Count); VulnerableCAs=$VulnerableCAs" `
                -Recommendation "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on Enterprise CAs using 'certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2' and restart CertSvc."
        }
        catch {
            Add-WFLFinding `
                -Title "AD CS ESC6 review failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC6" `
                -Evidence $_.Exception.Message
        }
    }


