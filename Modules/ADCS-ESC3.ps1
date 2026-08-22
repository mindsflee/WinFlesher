Register-WFLModule `
    -Name "ADCS-ESC3" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews Enrollment Agent certificate templates." `
        -Remediation @{
        Module        = 'ADCS-ESC3'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Restricts Enrollment Agent templates to authorized administrators only, mitigating ESC3 abuse vectors.'
        Impact        = 'Low. Hardens access permissions on enrollment agent templates.'
        VariableGuide = '$TemplateName: Enrollment Agent template name.'
        Code          = @'
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "ADCS ESC3 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC3" `
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

            $EnrollmentAgentOid = "1.3.6.1.4.1.311.20.2.1"
            $Results = @()

            foreach ($Template in $Templates) {
                $EKUs = @($Template.pKIExtendedKeyUsage)
                $EnrollFlag = $Template."msPKI-Enrollment-Flag"
                $ManagerApproval = (($EnrollFlag -band 2) -ne 0)
                $IsEnrollmentAgent = ($EKUs -contains $EnrollmentAgentOid)

                if ($IsEnrollmentAgent) {
                    $AclResult = Test-WFLBroadEnroll -DistinguishedName $Template.DistinguishedName

                    $Results += [PSCustomObject]@{
                        TemplateName        = $Template.Name
                        DisplayName         = $Template.DisplayName
                        EnrollmentAgentEKU  = $IsEnrollmentAgent
                        ManagerApproval     = $ManagerApproval
                        BroadEnroll         = $AclResult.BroadEnroll
                        ACLReadable         = $AclResult.ACLReadable
                        EnrollIdentities    = ($AclResult.EnrollIdentities -join "; ")
                        DistinguishedName   = $Template.DistinguishedName
                    }
                }
            }

            Add-WFLDetail -Name "ADCS-ESC3" -Data $Results

            $Confirmed = @($Results | Where-Object { $_.BroadEnroll -eq $true -and $_.ManagerApproval -ne $true })
            $Potential = @($Results | Where-Object { $_.BroadEnroll -ne $true -or $_.ManagerApproval -eq $true })

            $Severity = "Info"

            if ($Potential.Count -gt 0) {
                $Severity = "Low"
            }

            if ($Confirmed.Count -gt 0) {
                $Severity = "High"
            }

            Add-WFLFinding `
                -Title "AD CS ESC3 Enrollment Agent review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC3" `
                -Evidence "ConfirmedBroadEnrollNoApproval=$($Confirmed.Count); PotentialEnrollmentAgentTemplates=$($Potential.Count); TotalEnrollmentAgentTemplates=$($Results.Count)" `
                -Recommendation "Review Enrollment Agent templates, restrict enrollment, and require approval where appropriate."
        }
        catch {
            Add-WFLFinding `
                -Title "AD CS ESC3 review failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC3" `
                -Evidence $_.Exception.Message
        }
    }




