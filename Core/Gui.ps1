<#
.SYNOPSIS
    Winflesher - Attack Surface Security Framework by mindsflee (Alessandro Salzano)
.DESCRIPTION
    Winflesher is an advanced attack surface security assessment framework designed 
    to analyze, evaluate, and report on security postures, attack paths, and 
    remediation strategies.
.COMPONENT
    Gui Engine Module - [Gui.ps1]
#>

function Start-WFLGui {

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing


    $Theme = @{
        Background    = [System.Drawing.Color]::FromArgb(11, 14, 20)      # Deep Cobalt Black
        Sidebar      = [System.Drawing.Color]::FromArgb(18, 22, 31)      # Dark Slate
        Panel        = [System.Drawing.Color]::FromArgb(25, 31, 44)      # C2 Module Panel
        PanelHeader  = [System.Drawing.Color]::FromArgb(33, 41, 57)      # Active Highlight
        Accent       = [System.Drawing.Color]::FromArgb(0, 229, 255)     # Electric Cyan
        AccentHover  = [System.Drawing.Color]::FromArgb(0, 150, 200)     # Muted Cyan
        
        Text         = [System.Drawing.Color]::FromArgb(220, 230, 242)   # Bright Cyan-Grey
        Muted        = [System.Drawing.Color]::FromArgb(110, 130, 155)   # Tactical Grey
        
        Output       = [System.Drawing.Color]::FromArgb(7, 9, 13)        # Terminal Black
        Border       = [System.Drawing.Color]::FromArgb(45, 58, 80)      # Grid Border
        BorderActive = [System.Drawing.Color]::FromArgb(0, 180, 220)     # Active Border
    }


    function New-WFLBulletIcon {
        param([System.Drawing.Color]$Color)
        $bmp = New-Object System.Drawing.Bitmap(16, 16)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        
        $pen = New-Object System.Drawing.Pen($Theme.Border, 1)
        $g.DrawRectangle($pen, 3, 3, 9, 9)
        
        $brush = New-Object System.Drawing.SolidBrush($Color)
        $g.FillRectangle($brush, 5, 5, 6, 6)
        
        $pen.Dispose()
        $brush.Dispose()
        $g.Dispose()
        return $bmp
    }


    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "WinFlesher 2.0 [Attack Surface Security Framework]"
    $Form.WindowState = "Maximized"
    $Form.StartPosition = "CenterScreen"
    $Form.BackColor = $Theme.Background
    $Form.ForeColor = $Theme.Text
    $Form.MinimumSize = New-Object System.Drawing.Size(1200, 750)


    $Sidebar = New-Object System.Windows.Forms.Panel
    $Sidebar.Width = 270
    $Sidebar.Location = New-Object System.Drawing.Point(0,0)
    $Sidebar.Height = $Form.ClientSize.Height
    $Sidebar.Anchor = "Top,Bottom,Left"
    $Sidebar.BackColor = $Theme.Sidebar

    $Form.Controls.Add($Sidebar)


    $Main = New-Object System.Windows.Forms.Panel
    $Main.Location = New-Object System.Drawing.Point(270,0)
    $Main.Size = New-Object System.Drawing.Size(
        ($Form.ClientSize.Width - 270),
        $Form.ClientSize.Height
    )

    $Main.Anchor =
        [System.Windows.Forms.AnchorStyles]::Top `
        -bor [System.Windows.Forms.AnchorStyles]::Bottom `
        -bor [System.Windows.Forms.AnchorStyles]::Left `
        -bor [System.Windows.Forms.AnchorStyles]::Right

    $Main.BackColor = $Theme.Background

    $Form.Controls.Add($Main)


    $Form.Add_Resize({
        try {
            $clientW = [int]$Form.ClientSize.Width
            $clientH = [int]$Form.ClientSize.Height
            $targetW = [Math]::Max(100, ($clientW - 270))
            $targetH = [Math]::Max(100, $clientH)

            $Main.Size = New-Object System.Drawing.Size($targetW, $targetH)
        }
        catch {}
    })


    $LblTitle = New-Object System.Windows.Forms.Label
    $LblTitle.Text = "   WINFLESHER"
    $LblTitle.Location = New-Object System.Drawing.Point(16, 15)
    $LblTitle.Size = New-Object System.Drawing.Size(238, 32)
    $LblTitle.ForeColor = $Theme.Accent
    $LblTitle.BackColor = $Theme.Sidebar
    $LblTitle.Font = New-Object System.Drawing.Font("Consolas", 18, [System.Drawing.FontStyle]::Bold)

    $Sidebar.Controls.Add($LblTitle)

    $LblSub = New-Object System.Windows.Forms.Label
    $LblSub.Text = "          Attack Surface Framework"
    $LblSub.Location = New-Object System.Drawing.Point(16, 50)
    $LblSub.Size = New-Object System.Drawing.Size(238, 20)
    $LblSub.ForeColor = $Theme.Muted
    $LblSub.BackColor = $Theme.Sidebar
    $LblSub.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

    $Sidebar.Controls.Add($LblSub)

    $Sep1 = New-Object System.Windows.Forms.Panel
    $Sep1.Location = New-Object System.Drawing.Point(16, 78)
    $Sep1.Size = New-Object System.Drawing.Size(238, 1)
    $Sep1.BackColor = $Theme.Border
    $Sidebar.Controls.Add($Sep1)


    $IconBmp = New-WFLBulletIcon -Color $Theme.Accent

    function New-WFLButton {
        param(
            [string]$Text,
            [int]$Y,
            [switch]$IsPrimary
        )

        $Btn = New-Object System.Windows.Forms.Button
        $Btn.Text = "  $Text"
        $Btn.Location = New-Object System.Drawing.Point(16, $Y)
        $Btn.Size = New-Object System.Drawing.Size(238, 40)
        $Btn.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $Btn.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $Btn.Image = $IconBmp
        $Btn.TextImageRelation = [System.Windows.Forms.TextImageRelation]::ImageBeforeText

        $Btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $Btn.Font = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Bold)
        $Btn.FlatAppearance.BorderSize = 1

        if ($IsPrimary) {
            $Btn.BackColor = $Theme.PanelHeader
            $Btn.ForeColor = $Theme.Accent
            $Btn.FlatAppearance.BorderColor = $Theme.Accent
        } else {
            $Btn.BackColor = $Theme.Panel
            $Btn.ForeColor = $Theme.Text
            $Btn.FlatAppearance.BorderColor = $Theme.Border
        }

        $Btn.Add_MouseEnter({
            $this.BackColor = $Theme.PanelHeader
            $this.FlatAppearance.BorderColor = $Theme.BorderActive
        })
        $Btn.Add_MouseLeave({
            if (-not $IsPrimary) {
                $this.BackColor = $Theme.Panel
                $this.FlatAppearance.BorderColor = $Theme.Border
            } else {
                $this.BackColor = $Theme.PanelHeader
                $this.FlatAppearance.BorderColor = $Theme.Accent
            }
        })

        $Btn.TabStop = $false
        $Sidebar.Controls.Add($Btn)
        return $Btn
    }

    $BtnRun         = New-WFLButton "[RUN ASSESSMENT]" 92 -IsPrimary
    $BtnDashboard   = New-WFLButton "[DASHBOARD]"      137
    $BtnFindings    = New-WFLButton "[FINDINGS]"       182
    $BtnModules     = New-WFLButton "[MODULES]"        227
    $BtnAttack      = New-WFLButton "[ATTACK PATHS]"   272
    $BtnRemediation = New-WFLButton "[REMEDIATION]"  317

    $Sep2 = New-Object System.Windows.Forms.Panel
    $Sep2.Location = New-Object System.Drawing.Point(16, 367)
    $Sep2.Size = New-Object System.Drawing.Size(238, 1)
    $Sep2.BackColor = $Theme.Border
    $Sidebar.Controls.Add($Sep2)


    $LblCombo = New-Object System.Windows.Forms.Label
    $LblCombo.Text = "SELECT MODULE DETAIL:"
    $LblCombo.Location = New-Object System.Drawing.Point(16, 377)
    $LblCombo.Size = New-Object System.Drawing.Size(238, 18)
    $LblCombo.ForeColor = $Theme.Muted
    $LblCombo.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
    $Sidebar.Controls.Add($LblCombo)

    $ComboDetails = New-Object System.Windows.Forms.ComboBox
    $ComboDetails.Location = New-Object System.Drawing.Point(16, 399)
    $ComboDetails.Size = New-Object System.Drawing.Size(238, 30)
    $ComboDetails.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ComboDetails.BackColor = $Theme.Panel
    $ComboDetails.ForeColor = $Theme.Accent
    $ComboDetails.Font = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Bold)
    
    $ComboDetails.DrawMode = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ComboDetails.ItemHeight = 24
    
    $ComboDetails.Add_DrawItem({
        param($sender, $e)
        if ($e.Index -ge 0) {
            $e.DrawBackground()
            $brush = New-Object System.Drawing.SolidBrush($Theme.Accent)
            $text = $sender.Items[$e.Index]
            $e.Graphics.DrawString($text, $sender.Font, $brush, $e.Bounds.X, $e.Bounds.Y + 3)
            $brush.Dispose()
            $e.DrawFocusRectangle()
        }
    })
    
    $ComboDetails.Add_SelectedIndexChanged({
        Show-Details
    })

    $Sidebar.Controls.Add($ComboDetails)

    $Sep3 = New-Object System.Windows.Forms.Panel
    $Sep3.Location = New-Object System.Drawing.Point(16, 440)
    $Sep3.Size = New-Object System.Drawing.Size(238, 1)
    $Sep3.BackColor = $Theme.Border
    $Sidebar.Controls.Add($Sep3)

    $BtnHtml = New-WFLButton "[EXPORT HTML]"   448
    $BtnCsv  = New-WFLButton "[EXPORT CSV]"    493
    $BtnJson = New-WFLButton "[EXPORT JSON]"   538


    $Sep4 = New-Object System.Windows.Forms.Panel
    $Sep4.Location = New-Object System.Drawing.Point(16, ($Form.ClientSize.Height - 88))
    $Sep4.Size = New-Object System.Drawing.Size(238, 1)
    $Sep4.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $Sep4.BackColor = $Theme.Border
    $Sidebar.Controls.Add($Sep4)

    $BtnCloudConnect = New-WFLButton "[ENTRA ID CONNECT]" ($Form.ClientSize.Height - 80)
    $BtnCloudConnect.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left

    $Form.Add_Resize({
        try {
            $clientW = [int]$Form.ClientSize.Width
            $clientH = [int]$Form.ClientSize.Height
            $targetW = [Math]::Max(100, ($clientW - 270))
            $targetH = [Math]::Max(100, $clientH)

            $Main.Size = New-Object System.Drawing.Size($targetW, $targetH)
            
            $Sep4.Location = New-Object System.Drawing.Point(16, ($clientH - 88))
            $BtnCloudConnect.Location = New-Object System.Drawing.Point(16, ($clientH - 80))
        }
        catch {}
    })


    $Layout = New-Object System.Windows.Forms.TableLayoutPanel
    $Layout.Dock = [System.Windows.Forms.DockStyle]::Fill
    $Layout.RowCount = 2
    $Layout.ColumnCount = 1
    $Layout.BackColor = $Theme.Background
    $Layout.Padding = New-Object System.Windows.Forms.Padding(0)
    $Layout.Margin = New-Object System.Windows.Forms.Padding(0)

    $Layout.RowStyles.Clear()
    $Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
    $Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $Main.Controls.Add($Layout)


    $ScorePanel = New-Object System.Windows.Forms.Panel
    $ScorePanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $ScorePanel.BackColor = $Theme.Panel
    $ScorePanel.Margin = New-Object System.Windows.Forms.Padding(10, 10, 10, 5)
    $ScorePanel.Padding = New-Object System.Windows.Forms.Padding(18, 12, 18, 8)

    $Layout.Controls.Add($ScorePanel, 0, 0)

    $LblScore = New-Object System.Windows.Forms.Label
    $LblScore.Dock = [System.Windows.Forms.DockStyle]::Top
    $LblScore.Height = 38
    $LblScore.ForeColor = $Theme.Accent
    $LblScore.BackColor = $Theme.Panel
    $LblScore.Font = New-Object System.Drawing.Font("Consolas", 17, [System.Drawing.FontStyle]::Bold)

    $ScorePanel.Controls.Add($LblScore)

    $LblStats = New-Object System.Windows.Forms.Label
    $LblStats.Dock = [System.Windows.Forms.DockStyle]::Top
    $LblStats.Height = 35
    $LblStats.ForeColor = $Theme.Text
    $LblStats.BackColor = $Theme.Panel
    $LblStats.Font = New-Object System.Drawing.Font("Consolas", 11.5, [System.Drawing.FontStyle]::Bold)

    $ScorePanel.Controls.Add($LblStats)
    $LblStats.BringToFront()


    $OutputPanel = New-Object System.Windows.Forms.Panel
    $OutputPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $OutputPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 10)
    $OutputPanel.Margin = New-Object System.Windows.Forms.Padding(0)
    $OutputPanel.BackColor = $Theme.Background

    $Layout.Controls.Add($OutputPanel, 0, 1)


    $Output = New-Object System.Windows.Forms.TextBox
	
    $Output.Dock = [System.Windows.Forms.DockStyle]::Fill

    $Output.Multiline = $true
    $Output.ReadOnly = $true
    $Output.WordWrap = $false
    $Output.ScrollBars = [System.Windows.Forms.ScrollBars]::Both

    $Output.BackColor = $Theme.Output
    $Output.ForeColor = $Theme.Text
    $Output.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

    $Output.Font = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Regular)
    $Output.Margin = New-Object System.Windows.Forms.Padding(0)
    $Output.HideSelection = $false

    $OutputPanel.Controls.Add($Output)


    function Show-Text {
        param([string]$Text)
        if($null -eq $Text) { $Text = "" }
        $Output.SuspendLayout()
        $Output.Clear()
        $Output.Text = $Text
        $Output.SelectionStart = 0
        $Output.ScrollToCaret()
        $Output.ResumeLayout()
    }

    function Update-Score {
        try {
            $Score = Get-WFLScore
            if($null -eq $Score) { throw "No score available" }
            $LblScore.Text = "SYSTEM SCORE: $($Score.Score)/100  [STATUS: $($Score.Rating.ToUpper())]"
            $LblStats.Text = "FINDINGS: $($Score.Findings)  |  " +
                             "CRITICAL: $($Score.Critical)  |  " +
                             "HIGH: $($Score.High)  |  " +
                             "MED: $($Score.Medium)  |  " +
                             "LOW: $($Score.Low)  |  " +
                             "INFO: $($Score.Info)"
        }
        catch {
            $LblScore.Text = "SYSTEM SCORE: UNKNOWN [NO ASSESSMENT DATA]"
            $LblStats.Text = "Run assessment to populate telemetry and risk matrix."
        }
    }

    function Refresh-DetailCombo {
        $Current = $null
        if($ComboDetails.SelectedItem) {
            $Current = [string]$ComboDetails.SelectedItem
        }
        $ComboDetails.Items.Clear()
        if($Global:WinFlesher -and $Global:WinFlesher.Details) {
            foreach($Name in ($Global:WinFlesher.Details.Keys | Sort-Object)) {
                [void]$ComboDetails.Items.Add([string]$Name)
            }
        }
        if($ComboDetails.Items.Count -gt 0) {
            if($Current -and $ComboDetails.Items.Contains($Current)) {
                $ComboDetails.SelectedItem = $Current
            }
            else {
                $ComboDetails.SelectedIndex = 0
            }
        }
    }

    function Show-Dashboard {
        try {
            $Builder = New-Object System.Text.StringBuilder
            [void]$Builder.AppendLine("")
            [void]$Builder.AppendLine("========================== WINFLESHER DASHBOARD ==========================")
            [void]$Builder.AppendLine("")
            $Summary = Get-WFLSummaryByCategory
            if($null -eq $Summary) {
                [void]$Builder.AppendLine("[!] No summary data available. Execute assessment module.")
            }
            else {
                [void]$Builder.AppendLine(($Summary | Select-Object Category,Critical,High,Medium,Low,Info,Total | Format-Table | Out-String -Width 500))
            }
            Show-Text $Builder.ToString()
        }
        catch { Show-Text $_.Exception.Message }
    }

    function Show-Findings {
        try {
            if(-not $Global:WinFlesher -or -not $Global:WinFlesher.Findings) {
                Show-Text "[!] No findings available. Run assessment first."
                return
            }
            Show-Text ($Global:WinFlesher.Findings | Select-Object Severity,Category,Title | Format-Table | Out-String -Width 500)
        }
        catch { Show-Text $_.Exception.Message }
    }

    function Show-Modules {
        try {
            $Modules = Get-WFLModules
            if($null -eq $Modules) {
                Show-Text "[!] No modules found."
                return
            }
            Show-Text ($Modules | Format-Table | Out-String -Width 500)
        }
        catch { Show-Text $_.Exception.Message }
    }

    function Show-Details {
        try {
            $Name = [string]$ComboDetails.SelectedItem
            if ([string]::IsNullOrWhiteSpace($Name)) {
                Show-Text "[!] No detail module selected."
                return
            }
            
            $Global:WinFlesher.SelectedModule = $Name

            if (-not $Global:WinFlesher -or -not $Global:WinFlesher.Details) {
                Show-Text "[!] No details available. Run assessment first."
                return
            }
            if (-not $Global:WinFlesher.Details.ContainsKey($Name)) {
                Show-Text "[!] Selected detail module not found: $Name"
                return
            }
            $Data = $Global:WinFlesher.Details[$Name]
            if ($null -eq $Data) {
                Show-Text "[!] No detail data available for: $Name"
                return
            }
            Show-Text ($Data | Format-Table | Out-String -Width 500)
        }
        catch { Show-Text $_.Exception.Message }
    }

    function Show-Remediation {
        try {
            if (-not $Global:WinFlesher.Findings) {
                Show-Text "[!] No findings available. Run assessment first."
                return
            }

            $reportObjects = Get-FilteredRemediationReport -Findings $Global:WinFlesher.Findings

            if (-not $reportObjects -or $reportObjects.Count -eq 0) {
                Show-Text "[!] No remediation required."
                return
            }

            $Builder = New-Object System.Text.StringBuilder

            $HeaderWidth = 120
            $Title = "REMEDIATION GUIDE"

            $CenteredTitle = $Title.PadLeft(
                (($HeaderWidth - $Title.Length) / 2) + $Title.Length
            )

            [void]$Builder.AppendLine(("=" * $HeaderWidth))
            [void]$Builder.AppendLine($CenteredTitle)
            [void]$Builder.AppendLine(("=" * $HeaderWidth))
            [void]$Builder.AppendLine("")

            foreach ($item in $reportObjects) {
                [void]$Builder.AppendLine($item.FormattedBlock)
                [void]$Builder.AppendLine("")
            }

            Show-Text $Builder.ToString()
        }
        catch {
            Show-Text $_.Exception.Message
        }
    }


    $BtnRun.Add_Click({
        try {
            Show-Text "[*] Executing security assessment sequence..."
            [System.Windows.Forms.Application]::DoEvents()
            Start-WFLAssessment | Out-Null
            Refresh-DetailCombo
            Update-Score
            Show-Findings
        }
        catch { Show-Text $_.Exception.Message }
    })

    $BtnDashboard.Add_Click({ Show-Dashboard })
    $BtnFindings.Add_Click({ Show-Findings })
    $BtnModules.Add_Click({ Show-Modules })
    $BtnAttack.Add_Click({ Show-AttackPaths })
    $BtnRemediation.Add_Click({ Show-Remediation })

    $BtnHtml.Add_Click({
        try {
            if(Get-Command Export-WFLReportHtml -ErrorAction SilentlyContinue) {
                $Path = Export-WFLReportHtml
                [System.Windows.Forms.MessageBox]::Show($Path, "HTML Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Export-WFLReportHtml not found.", "HTML Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        }
        catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "HTML Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) }
    })

    $BtnCsv.Add_Click({
        try {
            if(Get-Command Export-WFLReportCsv -ErrorAction SilentlyContinue) {
                $Result = Export-WFLReportCsv
                $Message = if($Result -and $Result.Folder) { $Result.Folder } else { [string]$Result }
                [System.Windows.Forms.MessageBox]::Show($Message, "CSV Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Export-WFLReportCsv not found.", "CSV Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        }
        catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "CSV Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) }
    })

    $BtnJson.Add_Click({
        try {
            if(Get-Command Export-WFLReportJson -ErrorAction SilentlyContinue) {
                $Path = Export-WFLReportJson
                [System.Windows.Forms.MessageBox]::Show($Path, "JSON Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Export-WFLReportJson not found.", "JSON Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        }
        catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "JSON Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) }
    })

    $BtnCloudConnect.Add_Click({
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "A web browser window will now open for Microsoft Entra ID authentication.`nPlease complete the sign-in in your browser.", 
                "Authentication Required", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information
            )

            Show-Text @"
========================================================================
 WAITING FOR BROWSER AUTHENTICATION...
========================================================================
 [!] Please complete the login in the browser window that just opened.
 [ Target Module ]: Microsoft Graph / Entra ID
========================================================================
"@
            [System.Windows.Forms.Application]::DoEvents()

            $hasGraph = Get-Module -ListAvailable -Name "Microsoft.Graph.Applications" -ErrorAction SilentlyContinue
            $hasAzureAD = Get-Module -ListAvailable -Name "AzureAD" -ErrorAction SilentlyContinue

            if (-not $hasGraph -and -not $hasAzureAD) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Required modules (Microsoft.Graph.Applications or AzureAD) are not installed.`nRun: Install-Module Microsoft.Graph.Applications", 
                    "Cloud Connect Error", 
                    [System.Windows.Forms.MessageBoxButtons]::OK, 
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                Show-Text "[!] Cloud modules missing. Install them before connecting."
                return
            }

            if (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) {
                Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome
                
                $ctx = Get-MgContext
                if ($ctx) {
                    Show-Text "[+] Successfully connected to Entra ID Tenant: $($ctx.TenantId) as $($ctx.Account)"
                    [System.Windows.Forms.MessageBox]::Show("Connected successfully to Tenant:`n$($ctx.TenantId)", "Cloud Connect", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
            } elseif (Get-Command Connect-AzureAD -ErrorAction SilentlyContinue) {
                Connect-AzureAD | Out-Null
                $session = Get-AzureADCurrentSessionInfo
                if ($session) {
                    Show-Text "[+] Successfully connected to AzureAD Tenant: $($session.TenantDomain)"
                    [System.Windows.Forms.MessageBox]::Show("Connected successfully to AzureAD Tenant:`n$($session.TenantDomain)", "Cloud Connect", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Cloud Connect Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            Show-Text "[!] Cloud Connect Exception: $($_.Exception.Message)"
        }
    })

    Update-Score
    Refresh-DetailCombo
    Show-Dashboard

    [void]$Form.ShowDialog()
}
