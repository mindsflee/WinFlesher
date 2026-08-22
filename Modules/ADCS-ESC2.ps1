Register-WFLModule `
    -Name "ADCS-ESC2" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews templates with Any Purpose EKU or overly broad authentication-related usage." `
        -Remediation @{
        Module        = 'ADCS-ESC2'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Removes "Any Purpose" EKU or overly broad EKUs from certificate templates vulnerable to ESC2.'
        Impact        = 'Moderate. Restricts template usage to specific cryptographic tasks.'
        VariableGuide = '$TemplateName: Target vulnerable template.'
        Code          = @'
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "ADCS ESC2 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC2" `
                -Evidence "Active Directory discovery unavailable."
            return
        }

        function Test-WFLBroadEnroll {
            param([string]$DistinguishedName)

            $Result = [PSCustomObject]@{
                BroadEnroll = $false
                ACLReadable = $false
                EnrollIdentities = @()
            }

            try {
                $Result.ACLReadable = $true

                $EnrollGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                $BroadPatterns = @(
                    "Domain Users",
                    "Authenticated Users",
                    "Everyone",
                    "Domain Computers"
                )

                foreach ($Ace in $Acl.Access) {
                    $Identity = [string]$Ace.IdentityReference
                    $ObjectType = [string]$Ace.ObjectType

                    $HasEnrollRight = (
                        $ObjectType -eq $EnrollGuid -or
                        $Ace.ActiveDirectoryRights -match "ExtendedRight"
                    )

                    if ($HasEnrollRight) {
                        foreach ($Pattern in $BroadPatterns) {
                            if ($Identity -like "*$Pattern*") {
                                $Result.BroadEnroll = $true
                                $Result.EnrollIdentities += $Identity
                            }
                        }
                    }
                }
            }
            catch {}

            return $Result
        }

        try {
            $ConfigNC = (Get-ADRootDSE).configurationNamingContext
            $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

            $Templates = @(Get-ADObject `
                -SearchBase $TemplatePath `
                -LDAPFilter "(objectClass=pKICertificateTemplate)" `
                -Properties cn,displayName,pKIExtendedKeyUsage,msPKI-Enrollment-Flag `
                -ErrorAction Stop)

            $AnyPurposeOid = "2.5.29.37.0"
            $Results = @()

            foreach ($Template in $Templates) {
                $EKUs = @($Template.pKIExtendedKeyUsage)
                $EnrollFlag = $Template."msPKI-Enrollment-Flag"
                $ManagerApproval = (($EnrollFlag -band 2) -ne 0)
                $HasAnyPurpose = ($EKUs -contains $AnyPurposeOid)

                if ($HasAnyPurpose -and -not $ManagerApproval) {
                    $AclResult = Test-WFLBroadEnroll -DistinguishedName $Template.DistinguishedName

                    $Results += [PSCustomObject]@{
                        TemplateName      = $Template.Name
                        DisplayName       = $Template.DisplayName
                        AnyPurposeEKU     = $HasAnyPurpose
                        ManagerApproval   = $ManagerApproval
                        BroadEnroll       = $AclResult.BroadEnroll
                        ACLReadable       = $AclResult.ACLReadable
                        EnrollIdentities  = ($AclResult.EnrollIdentities -join "; ")
                        DistinguishedName = $Template.DistinguishedName
                    }
                }
            }

            Add-WFLDetail -Name "ADCS-ESC2" -Data $Results

            $Confirmed = @($Results | Where-Object { $_.BroadEnroll -eq $true })
            $Potential = @($Results | Where-Object { $_.BroadEnroll -ne $true })

            $Severity = "Info"

            if ($Potential.Count -gt 0) {
                $Severity = "Medium"
            }

            if ($Confirmed.Count -gt 0) {
                $Severity = "High"
            }

            Add-WFLFinding `
                -Title "AD CS ESC2 Any Purpose EKU review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC2" `
                -Evidence "ConfirmedBroadEnroll=$($Confirmed.Count); PotentialTemplates=$($Potential.Count); TotalCandidateTemplates=$($Results.Count)" `
                -Recommendation "Review templates with Any Purpose EKU and broad enrollment. Restrict enrollment and require approval where appropriate."
        }
        catch {
            Add-WFLFinding `
                -Title "AD CS ESC2 review failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC2" `
                -Evidence $_.Exception.Message
        }
    }




