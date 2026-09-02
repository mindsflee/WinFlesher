Register-WFLModule `
    -Name "ADCS-Discovery" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1590.001" `
    -Tactic "Discovery" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Discovers AD CS Enterprise CA objects and published certificate templates." `
   -Remediation @{
        Module        = 'ADCS-Discovery.ps1'
        Category      = 'Active Directory Security'
        Type          = 'Specific'
        Description   = 'Mitigate AD CS vulnerabilities by disabling or amending vulnerable certificate templates.'
        Impact        = 'Prevents certificate configuration abuse for identity theft and Domain Admin escalation.'
        VariableGuide = 'Replace [Vulnerable_Name_Model] with the template name identified by the analysis.'
        Code          = @'
$templateName = "[Vulnerable_Name_Model]"
Set-ADObject -Identity "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=dominio,DC=local" -Replace @{gPCUserAuthorizationRequirement=1}
Write-Host "[!] Certificate template $templateName disabled/secured." -ForegroundColor Yellow
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "AD CS discovery unavailable" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-Discovery" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."
            return
        }

        try {
            $ConfigNC = (Get-ADRootDSE).configurationNamingContext
            $CAPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
            $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

            $CAs = @(Get-ADObject `
                -SearchBase $CAPath `
                -LDAPFilter "(objectClass=pKIEnrollmentService)" `
                -Properties cn,dNSHostName,certificateTemplates `
                -ErrorAction SilentlyContinue |
                Select-Object Name, DistinguishedName, dNSHostName, certificateTemplates)

            $Templates = @(Get-ADObject `
                -SearchBase $TemplatePath `
                -LDAPFilter "(objectClass=pKICertificateTemplate)" `
                -Properties cn,displayName,pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag `
                -ErrorAction SilentlyContinue |
                Select-Object Name, DistinguishedName, displayName, pKIExtendedKeyUsage, msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag)

            Add-WFLDetail -Name "ADCS-Discovery-CAs" -Data $CAs
            Add-WFLDetail -Name "ADCS-Discovery-Templates" -Data $Templates

            $Severity = "Info"

            if ($CAs.Count -gt 0) {
                $Severity = "Low"
            }

            Add-WFLFinding `
                -Title "AD CS discovery review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-Discovery" `
                -Evidence "EnterpriseCAs=$($CAs.Count); CertificateTemplates=$($Templates.Count)" `
                -Recommendation "Review published CAs and certificate templates. Use Show-WFLDetails -Name ADCS-Discovery-CAs and Show-WFLDetails -Name ADCS-Discovery-Templates."
        }
        catch {
            Add-WFLFinding `
                -Title "AD CS discovery failed" `
                -Severity "Info" `
                -Category "Active Directory Certificate Services" `
                -Source "ADCS-Discovery" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify RSAT ActiveDirectory module and permissions."
        }
    }


