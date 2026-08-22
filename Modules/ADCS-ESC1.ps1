Register-WFLModule `
    -Name "ADCS-ESC1" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews certificate templates potentially exposed to ESC1-like misconfiguration." `
        -Remediation @{
        Module        = 'ADCS-ESC1'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Secures certificate templates vulnerable to ESC1 (ENROLLEE_SUPPLIES_SUBJECT and manager approval disabled with client auth EKU).'
        Impact        = 'Moderate. Disables insecure subject name enrollment flags on vulnerable templates.'
        VariableGuide = '$TemplateName: The name of the vulnerable AD CS template.'
        Code          = @'
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "ADCS ESC1 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC1" `
                -Evidence "Active Directory discovery unavailable."
            return
        }

        function Test-WFLBroadEnroll {
           param(
[object]$Template
)

            $Result = [PSCustomObject]@{
                BroadEnroll = $false
                ACLReadable = $false
                EnrollIdentities = @()
            }

           try {

    $Acl = $Template.nTSecurityDescriptor

    if ($null -eq $Acl)
    {
        return $Result
    }

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
    -Properties cn,
                displayName,
                pKIExtendedKeyUsage,
                msPKI-Certificate-Name-Flag,
                msPKI-Enrollment-Flag,
                nTSecurityDescriptor `
                -ErrorAction Stop)

            $ClientAuthOids = @(
                "1.3.6.1.5.5.7.3.2",
                "1.3.6.1.4.1.311.20.2.2"
            )

            $Results = @()

            foreach ($Template in $Templates) {
                $NameFlag = $Template."msPKI-Certificate-Name-Flag"
                $EnrollFlag = $Template."msPKI-Enrollment-Flag"
                $EKUs = @($Template.pKIExtendedKeyUsage)

                $SupplyInRequest = (($NameFlag -band 1) -ne 0)
                $ManagerApproval = (($EnrollFlag -band 2) -ne 0)
                $ClientAuthCapable = $false

                foreach ($Oid in $ClientAuthOids) {
                    if ($EKUs -contains $Oid) {
                        $ClientAuthCapable = $true
                    }
                }

              $AclResult = Test-WFLBroadEnroll -Template $Template

                if ($SupplyInRequest -and $ClientAuthCapable -and -not $ManagerApproval) {
                    $Results += [PSCustomObject]@{
                        TemplateName       = $Template.Name
                        DisplayName        = $Template.DisplayName
                        SupplyInRequest    = $SupplyInRequest
                        ClientAuthCapable  = $ClientAuthCapable
                        ManagerApproval    = $ManagerApproval
                        BroadEnroll        = $AclResult.BroadEnroll
                        ACLReadable        = $AclResult.ACLReadable
                        EnrollIdentities   = ($AclResult.EnrollIdentities -join "; ")
                        DistinguishedName  = $Template.DistinguishedName
                    }
                }
            }

            Add-WFLDetail -Name "ADCS-ESC1" -Data $Results

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
                -Title "AD CS ESC1 template exposure review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC1" `
                -Evidence "ConfirmedBroadEnroll=$($Confirmed.Count); PotentialTemplates=$($Potential.Count); TotalCandidateTemplates=$($Results.Count)" `
                -Recommendation "Review templates with supply-in-request and client authentication EKUs. Remove broad enrollment, require manager approval where appropriate, and restrict certificate use."
        }
        catch {
            Add-WFLFinding `
                -Title "AD CS ESC1 review failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC1" `
                -Evidence $_.Exception.Message
        }
    }




