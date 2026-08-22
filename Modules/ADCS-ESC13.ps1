Register-WFLModule `
    -Name "ADCS-ESC13" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews certificate templates related to privileged authentication." `
        -Remediation @{
        Module        = 'ADCS-ESC13'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Reviews and remediates certificate templates linked to dangerous issuance policies or access control misconfigurations.'
        Impact        = 'Low. Hardens issuance policy mapping requirements.'
        VariableGuide = 'Template configuration attributes.'
        Code          = @'
'@
    } -Run {

        try {

            $ConfigNC = (Get-ADRootDSE).configurationNamingContext
			
			$OIDs = Get-ADObject `
    -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
    -LDAPFilter "(objectClass=msPKI-Enterprise-Oid)" `
    -Properties displayName,msDS-OIDToGroupLink,msPKI-Cert-Template-OID `
    -ErrorAction SilentlyContinue

            $Templates = Get-ADObject `
                -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC" `
                -LDAPFilter "(objectClass=pKICertificateTemplate)" `
                -Properties displayName,pKIExtendedKeyUsage,msPKI-Certificate-Policy

            $Interesting = @()

foreach ($Template in $Templates)
{
    $Policies = @($Template."msPKI-Certificate-Policy")

    foreach ($Policy in $Policies)
    {
        $LinkedOID = $OIDs | Where-Object {

            $_."msPKI-Cert-Template-OID" -eq $Policy -or
            $_.DisplayName -eq $Policy
        }

        if ($LinkedOID)
        {
            foreach ($OID in $LinkedOID)
            {
                if ($OID."msDS-OIDToGroupLink")
                {
                    $Interesting += [PSCustomObject]@{
                        TemplateName = $Template.displayName
                        PolicyOID    = $Policy
                        GroupLink    = $OID."msDS-OIDToGroupLink"
                    }
                }
            }
        }
    }
}

            Add-WFLDetail `
                -Name "ADCS-ESC13" `
                -Data $Interesting

          $Severity = "Info"

if ($Interesting.Count -gt 0)
{
    $Severity = "High"
}

            Add-WFLFinding `
                -Title "AD CS ESC13 template review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC13" `
                -Evidence "TemplatesReviewed=$($Interesting.Count)" `
                -Recommendation "Review certificate-to-group mappings and privileged authentication templates."
        }
        catch {

            Add-WFLFinding `
                -Title "AD CS ESC13 review failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-ESC13" `
                -Evidence $_.Exception.Message
        }
    }


