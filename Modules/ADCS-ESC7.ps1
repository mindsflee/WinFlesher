Register-WFLModule `
    -Name "ADCS-ESC7" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Audits ACLs on Enterprise Certification Authorities for unauthorized ManageCA or ManageCertificates rights (ESC7 exposure)." `
        -Remediation @{
        Module        = 'ADCS-ESC7'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Removes unauthorized ManageCA and ManageCertificates access rights from non-admin accounts on Certification Authorities.'
        Impact        = 'Low. Secures CA administration permissions.'
        VariableGuide = '$CAName: Name of the Enterprise Certification Authority.'
        Code          = @'
'@
    } -Run {
        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding -Title "AD CS ESC7 review unavailable" -Severity "Info" -Category "Active Directory Certificate Services" -Source "ADCS-ESC7" -Evidence "AD unavailable."
            return
        }

        try {
            $ConfigDN = (Get-ADRootDSE).ConfigurationNamingContext
            $EnrollmentServicesContainer = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigDN"
            
            $ExposedCAs = @()
            $CAs = Get-ADObject -SearchBase $EnrollmentServicesContainer -Filter * -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

            $DangerousCARights = "GenericAll|FullControl|WriteDacl|WriteOwner"

            foreach ($CA in $CAs) {
                $Acl = $CA.nTSecurityDescriptor
                if ($null -eq $Acl) { continue }
                
                foreach ($Access in $Acl.Access) {
                    if ($Access.AccessControlType -eq "Allow") {
                        $Identity = $Access.IdentityReference.Value
                        
                      if (
    $Identity -notmatch "Domain Admins|Enterprise Admins|Administrator|Administrators|SYSTEM|Key Admins|Enterprise Key Admins|Domain Controllers|Enterprise Domain Controllers|Cert Publishers" -and -not $Identity.EndsWith('$')
) {if ($Access.ActiveDirectoryRights -match $DangerousCARights) {

    $Rights = $Access.ActiveDirectoryRights.ToString()

    $SeverityRank = "Medium"
    $Exploitability = "Potential"

    if ($Rights -match "GenericAll|FullControl")
    {
        $SeverityRank = "Critical"
        $Exploitability = "Likely"
    }
    elseif ($Rights -match "WriteDacl|WriteOwner")
    {
        $SeverityRank = "High"
        $Exploitability = "Likely"

        if (
            $Identity -match "Authenticated Users|Domain Users|Everyone"
        )
        {
            $SeverityRank = "Critical"
        }
    }

    $ExposedCAs += [PSCustomObject]@{
        CAName         = $CA.Name
        Principal      = $Identity
        GrantedRights  = $Rights
        Severity       = $SeverityRank
        Exploitability = $Exploitability
        DN             = $CA.DistinguishedName
    }
}
                        }
                    }
                }
            }

            Add-WFLDetail -Name "ADCS-ESC7" -Data $ExposedCAs

          $Severity = "Info"

if (($ExposedCAs | Where-Object {$_.Severity -eq "Critical"}).Count -gt 0)
{
    $Severity = "Critical"
}
elseif (($ExposedCAs | Where-Object {$_.Severity -eq "High"}).Count -gt 0)
{
    $Severity = "High"
}
elseif (($ExposedCAs | Where-Object {$_.Severity -eq "Medium"}).Count -gt 0)
{
    $Severity = "Medium"
}

            Add-WFLFinding `
                -Title "AD CS ESC7 CA Management Exposure Review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC7" `
                -Evidence "Identified $($ExposedCAs.Count) Enterprise CA object ACL(s) granting dangerous management rights to non-admin accounts." `
                -Recommendation "Remove ManageCA, ManageCertificates, WriteDacl, and WriteOwner rights on CA objects from unprivileged users and groups."
        }
        catch {
            Add-WFLFinding -Title "ADCS ESC7 review failed" -Severity "Info" -Category "Active Directory Certificate Services" -Source "ADCS-ESC7" -Evidence $_.Exception.Message
        }
    }


