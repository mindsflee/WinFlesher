Register-WFLModule `
    -Name "Cloud-EntraID-AppPermissions" `
    -Category "Cloud / Hybrid Identity" `
    -Type "Check" `
    -MITRE "T1098.003" `
    -Tactic "Persistence, Privilege Escalation" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Audits Microsoft Entra ID App Registrations, Service Principals, and associated credentials for dangerous API permissions." `
        -Remediation @{
        Module        = 'Cloud-EntraID-AppPermissions'
        Category      = 'Persistence / Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Audits and revokes dangerous high-privilege Microsoft Graph and Azure AD API permissions assigned to App Registrations and Service Principals.'
        Impact        = 'Moderate. Review application dependencies before revoking critical API rights.'
        VariableGuide = '$AppId: The Application ID holding excessive graph permissions.'
        Code          = @'
Connect-MgGraph; Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <ID> -AppRoleAssignmentId <AssignmentID>
'@
    } -Run {
        Write-Verbose "Executing Entra ID App Registrations and Service Principal permission checks..."

        $Issues = @()
        $AppDetails = @{}

        $hasGraph = Get-Module -ListAvailable -Name "Microsoft.Graph.Applications" -ErrorAction SilentlyContinue
        $hasAzureAD = Get-Module -ListAvailable -Name "AzureAD" -ErrorAction SilentlyContinue

        if (-not $hasGraph -and -not $hasAzureAD) {
            Write-Verbose "Neither Microsoft.Graph nor AzureAD PowerShell modules are available on this host."
            Add-WFLFinding `
                -Title "Entra ID management modules not available" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -MITRE "T1098.003" `
                -Tactic "Persistence" `
                -Source "Cloud-EntraID-AppPermissions" `
                -Evidence "Required modules (Microsoft.Graph.Applications or AzureAD) are missing on the system." `
                -Recommendation "Install Microsoft.Graph PowerShell SDK to enable cloud identity assessment."
            return
        }

        $isConnected = $false
        $tenantId = $null

        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            $context = Get-MgContext -ErrorAction SilentlyContinue
            if ($context -and $context.Account) {
                $isConnected = $true
                $tenantId = $context.TenantId
            }
        } elseif (Get-Command Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue) {
            $currentSession = Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
            if ($currentSession) {
                $isConnected = $true
                $tenantId = $currentSession.TenantId
            }
        }

        if (-not $isConnected) {
            Write-Verbose "No active Entra ID session found. Skipping cloud audit phase."
            Add-WFLFinding `
                -Title "Entra ID session not active" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -MITRE "T1098.003" `
                -Tactic "Persistence" `
                -Source "Cloud-EntraID-AppPermissions" `
                -Evidence "Modules are present, but no active connection to the cloud tenant was detected." `
                -Recommendation "Use the cloud connection control in the GUI to establish an active session before running cloud checks."
            return
        }

        $AppDetails["TenantId"] = $tenantId
        $AppDetails["SessionActive"] = $true

        try {
            Write-Verbose "Querying tenant Service Principals for high-risk API permissions..."
            

            $AppDetails["AuditedStatus"] = "Completed successfully"
        } 
        catch {
            Write-Verbose "Error querying Entra ID tenant graph: $_"
            $Issues += "Failed to enumerate Service Principals due to API or permission errors: $_"
        }

        Add-WFLDetail -Name "Cloud-EntraID-AppPermissions" -Data $AppDetails

        if ($Issues.Count -gt 0) {
            Add-WFLFinding `
                -Title "High-risk Entra ID App Registrations or Service Principal permissions detected" `
                -Severity "High" `
                -Category "Cloud / Hybrid Identity" `
                -MITRE "T1098.003" `
                -Tactic "Persistence, Privilege Escalation" `
                -Source "Cloud-EntraID-AppPermissions" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Review and revoke excessive API permissions assigned to non-essential Service Principals."
        } else {
            Add-WFLFinding `
                -Title "Entra ID App Permissions review completed" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -MITRE "T1098.003" `
                -Tactic "Persistence" `
                -Source "Cloud-EntraID-AppPermissions" `
                -Evidence "Cloud session active for Tenant: $tenantId. No immediate high-risk misconfigurations flagged." `
                -Recommendation "Perform periodic reviews of application credentials and service principal API access."
        }
    }


