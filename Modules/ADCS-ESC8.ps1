Register-WFLModule `
    -Name "ADCS-ESC8" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Checks for potentially exposed AD CS HTTP enrollment endpoints." `
        -Remediation @{
        Module        = 'ADCS-ESC8'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Disables HTTP-based enrollment endpoints (CertSrv Web Enrollment) or enforces EPA (Extended Protection for Authentication) to stop NTLM relay attacks.'
        Impact        = 'Moderate. Disabling web enrollment endpoints or enabling EPA secures the CA against coercion and relay.'
        VariableGuide = 'IIS Web Enrollment site binding configuration.'
        Code          = @'
Disable-WindowsOptionalFeature -Online -FeatureName "CertificateServicesWebEnrollment"
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "ADCS ESC8 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC8" `
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
                $HostName = [string]$CA.dNSHostName

                if ([string]::IsNullOrWhiteSpace($HostName)) {
                    continue
                }

                $HttpUrl = "http://$HostName/certsrv/"
                $HttpsUrl = "https://$HostName/certsrv/"

                $HttpReachable = $false
                $HttpsReachable = $false
                $HttpStatus = ""
                $HttpsStatus = ""

                try {
                    $Response = Invoke-WebRequest -Uri $HttpUrl -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    $HttpReachable = $true
                    $HttpStatus = [string]$Response.StatusCode
                }
                catch {
                    $HttpStatus = $_.Exception.Message
                }

                try {
                    $Response = Invoke-WebRequest -Uri $HttpsUrl -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    $HttpsReachable = $true
                    $HttpsStatus = [string]$Response.StatusCode
                }
                catch {
                    $HttpsStatus = $_.Exception.Message
                }

                $Results += [PSCustomObject]@{
                    CAName         = $CA.Name
                    DNSHostName    = $HostName
                    HTTPUrl        = $HttpUrl
                    HTTPReachable  = $HttpReachable
                    HTTPStatus     = $HttpStatus
                    HTTPSUrl       = $HttpsUrl
                    HTTPSReachable = $HttpsReachable
                    HTTPSStatus    = $HttpsStatus
                }
            }

            Add-WFLDetail -Name "ADCS-ESC8" -Data $Results

            $HttpExposed = @($Results | Where-Object { $_.HTTPReachable -eq $true })
            $HttpsOnly = @($Results | Where-Object { $_.HTTPReachable -ne $true -and $_.HTTPSReachable -eq $true })

            $Severity = "Info"

            if ($HttpsOnly.Count -gt 0) {
                $Severity = "Low"
            }

            if ($HttpExposed.Count -gt 0) {
                $Severity = "High"
            }

            Add-WFLFinding `
                -Title "AD CS ESC8 HTTP enrollment endpoint review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC8" `
                -Evidence "HTTPReachable=$($HttpExposed.Count); HTTPSOnly=$($HttpsOnly.Count); CheckedCAs=$($Results.Count)" `
                -Recommendation "Review AD CS web enrollment endpoints. Disable unnecessary HTTP enrollment endpoints or enforce secure configurations where required."
        }
        catch {
            Add-WFLFinding `
                -Title "AD CS ESC8 review failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC8" `
                -Evidence $_.Exception.Message
        }
    }



