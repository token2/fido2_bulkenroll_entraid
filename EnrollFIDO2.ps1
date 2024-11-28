# Function to check and install a module if not present
function Ensure-Module {
    param (
        [string]$ModuleName,
        [string]$InstallCommand = $ModuleName # Defaults to the same name as the module
    )
    # Check if the module is installed
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Output "Module '$ModuleName' is not installed. Installing..."
        try {
            Install-Module -Name $InstallCommand -Scope CurrentUser -Force -AllowClobber
            Write-Output "Module '$ModuleName' installed successfully."
        } catch {
            Write-Error "Failed to install module '$ModuleName': $_"
        }
    } else {
        Write-Output "Module '$ModuleName' is already installed."
    }
}

# Ensure Connect-MgGraph is installed
Ensure-Module -ModuleName "Microsoft.Graph" -InstallCommand "Microsoft.Graph"

# Ensure dsinternals.passkeys is installed
Ensure-Module -ModuleName "DSInternals.PassKeys"


# Function to generate a random PIN (6 digits, PIN+ complexity)
function Generate-RandomPin {
    do {
        # Generate a random 6-digit PIN
        $pin = -join ((48..57) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        
        # Check for sequential numbers in ascending or descending order
        $isSequential = ($pin -match '012345|123456|234567|345678|456789|567890|678901|789012|890123|901234' -or
                          $pin -match '987654|876543|765432|654321|543210|432109|321098|210987|109876|098765')

        # Check for repeated digits
        $hasRepeatedDigits = ($pin -match '(\d)\1{5,}' -or $pin -match '(\d)\1{3,}')
        
        # Check for palindromes (mirror numbers)
        $isPalindrome = ($pin -eq ([string]::Join("", ($pin.ToCharArray() | ForEach-Object { $_ })[-1..-6])))

    } while ($isSequential -or $hasRepeatedDigits -or $isPalindrome)

    return $pin
}
 


function Show-NativeDialog {
    param (
        [ScriptBlock]$dialogAction
    )
    $dialogAction.Invoke()
    [User32]::SetForegroundWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
}


function Show-ModalDialog {
    param (
        [System.Windows.Forms.Form]$dialog
    )
    $dialog.StartPosition = "CenterParent"
    $dialog.ShowDialog() | Out-Null
}

function Bring-MainWindowToForeground {
    if (-not ([System.Management.Automation.PSTypeName]'User32').Type) {
        Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            public class User32 {
                [DllImport("user32.dll")]
                public static extern bool SetForegroundWindow(IntPtr hWnd);
            }
"@
    }

    $form.Activate()
    [User32]::SetForegroundWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
}

# Import required modules
Add-Type -AssemblyName System.Windows.Forms

# Global variables
$serialOutput = "None"
$logFilePath = "provisioning.log"

# Define Registry Path
$regPath = "HKCU:\Software\Token2BulkFido"
 
$propertyName = "TenantId"
$defaultValue = "TENANTNAME.onmicrosoft.com"  # Replace with the default value you want

# Check if the registry path exists
if (-not (Test-Path $regPath)) {
    # Create the registry path if it does not exist
    New-Item -Path $regPath -Force | Out-Null
 
}
# Check if the property exists
try {
    $existingProperty = Get-ItemProperty -Path $regPath -Name $propertyName -ErrorAction Stop
     
} catch {
    # Property does not exist; create it
    New-ItemProperty -Path $regPath -Name $propertyName -Value $defaultValue -PropertyType String -Force | Out-Null
    Write-Output "Property '$propertyName' created with value: $defaultValue"
}

# Create the main form
$form = New-Object System.Windows.Forms.Form

$form.Text = "FIDO Key Registration"
$form.Size = New-Object System.Drawing.Size(500, 350)
$form.StartPosition = "CenterScreen"

# Create a label and text box for Tenant ID input
$labelTenant = New-Object System.Windows.Forms.Label
$labelTenant.Text = "Enter Tenant ID:"
$labelTenant.Location = New-Object System.Drawing.Point(20, 20)
$form.Controls.Add($labelTenant)

$textTenantId = New-Object System.Windows.Forms.TextBox
$textTenantId.Location = New-Object System.Drawing.Point(150, 20)
$textTenantId.Width = 300
$form.Controls.Add($textTenantId)

# Retrieve Tenant Name from Registry
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
} else {
    try {
        $tenantIdFromRegistry = (Get-ItemProperty -Path $regPath -Name "TenantId").TenantId
        if (-not [string]::IsNullOrWhiteSpace($tenantIdFromRegistry)) {
            $textTenantId.Text = $tenantIdFromRegistry
        }
    } catch {
        Write-Host "Failed to retrieve Tenant ID from registry: $_"
    }
}

# Create a button to select the CSV or text file
$btnSelectFile = New-Object System.Windows.Forms.Button
$btnSelectFile.Text = "Select File"
$btnSelectFile.Location = New-Object System.Drawing.Point(20, 60)
$form.Controls.Add($btnSelectFile)

# Create a label to display the selected file path
$labelFilePath = New-Object System.Windows.Forms.Label
$labelFilePath.AutoSize = $true
$labelFilePath.Location = New-Object System.Drawing.Point(150, 65)
$labelFilePath.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($labelFilePath)

# Create a checkbox for setting a random PIN
$chkSetRandomPin = New-Object System.Windows.Forms.CheckBox
$chkSetRandomPin.Text = "Set Random PIN"
$chkSetRandomPin.Width = 200  # Set the width to 200 pixels
$chkSetRandomPin.Location = New-Object System.Drawing.Point(20, 100)
$form.Controls.Add($chkSetRandomPin)

# Add a checkbox for "Copy generated PIN to clipboard"
$checkBoxCopyToClipboard = New-Object System.Windows.Forms.CheckBox
$checkBoxCopyToClipboard.Text = "Copy generated PIN to clipboard"
$checkBoxCopyToClipboard.AutoSize = $true
$checkBoxCopyToClipboard.Location = New-Object System.Drawing.Point(20, 140) # Adjust as needed

$form.Controls.Add($checkBoxCopyToClipboard)


# Create a checkbox for forcing PIN change
$chkForcePinChange = New-Object System.Windows.Forms.CheckBox
$chkForcePinChange.Text = "Force PIN Change"
$chkForcePinChange.Width = 200  # Set the width to 200 pixels
$chkForcePinChange.Location = New-Object System.Drawing.Point(20, 120)
$form.Controls.Add($chkForcePinChange)

# Create a button to set the log file path
$btnSetLogFile = New-Object System.Windows.Forms.Button
$btnSetLogFile.Text = "Set Log File"
$btnSetLogFile.Location = New-Object System.Drawing.Point(20, 180)
$form.Controls.Add($btnSetLogFile)

# Create a label to display the selected log file path
$labelLogFilePath = New-Object System.Windows.Forms.Label
$labelLogFilePath.Text = $logFilePath
$labelLogFilePath.AutoSize = $true
$labelLogFilePath.Location = New-Object System.Drawing.Point(150, 180)
$labelLogFilePath.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($labelLogFilePath)

# Define file selection logic
$btnSelectFile.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter =  "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $labelFilePath.Text = $openFileDialog.FileName
    }
})

# Define log file selection logic
$btnSetLogFile.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*"
    $saveFileDialog.DefaultExt = "csv"
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $labelLogFilePath.Text = $saveFileDialog.FileName
        $logFilePath = $saveFileDialog.FileName
    }
})




# Define the Instruction Label
$lblInstruction = New-Object System.Windows.Forms.Label
$lblInstruction.Text = "  plug the first user's key before proceeding"
$lblInstruction.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)
$lblInstruction.AutoSize = $true
$lblInstruction.Location = New-Object System.Drawing.Point(20, 230)
$form.Controls.Add($lblInstruction)

# Define Proceed button logic
$btnProceed = New-Object System.Windows.Forms.Button
$btnProceed.Text = "Proceed"
$btnProceed.Width = 200
$btnProceed.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)
$btnProceed.Location = New-Object System.Drawing.Point(20, 260)  # Adjusted lower than the label
$form.Controls.Add($btnProceed)

 
 
 $btnProceed.Add_Click({
    Write-Host "Checking entered data"
	    $form.Visible = $false

    try {
        $tenantId = $textTenantId.Text
        $filePath = $labelFilePath.Text

        if (-not $tenantId) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a Tenant ID.", "Error")
			$form.Visible = $true
            return
        }

        if (-not $filePath -or -not (Test-Path $filePath)) {
            [System.Windows.Forms.MessageBox]::Show("Please select a valid CSV file.", "Error")
			$form.Visible = $true
            return
        }

        Set-ItemProperty -Path $regPath -Name "TenantId" -Value $tenantId -Force
		Write-Host "Connecting to MSGraph"
        Connect-MgGraph -Scopes 'UserAuthenticationMethod.ReadWrite.All' -TenantId $tenantId -NoWelcome

        $upns = Import-Csv $filePath | Select-Object -ExpandProperty UPN
		$totalUsers = $upns.Count
		$currentIndex = 0
        foreach ($upn in $upns) {
            if (-not $upn) { continue }
			    $currentIndex++

            # Fetch the serial number using read_serial_t2.exe
            try {
                $serialOutput = (& ".\read_serial_t2.exe").Trim()
                if ([string]::IsNullOrWhiteSpace($serialOutput) -or $serialOutput -eq "None") {
                    [System.Windows.Forms.MessageBox]::Show("No valid serial number detected . Skipping.", "Error")
                    Write-Host "No valid serial number for $upn. Skipping."
                    continue
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error reading serial number .  Skipping.", "Error")
                Write-Host "Error reading serial number for  "
                continue
            }

            $randomPin = $null
            if ($chkSetRandomPin.Checked) {
                $randomPin = Generate-RandomPin
				# Copy generated PIN to clipboard if the checkbox is checked
if ($checkBoxCopyToClipboard.Checked) {
	Write-Host "Set PIN to ClipBoard $randomPin"
    Set-Clipboard -Value $randomPin
}

            }

            # Create an intermediate popup for the user
            $serialPopup = New-Object System.Windows.Forms.Form
            $serialPopup.Text = "Add Key for $upn"
            $serialPopup.Size = New-Object System.Drawing.Size(400, 200)
            $serialPopup.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
			 
            #$serialPopup.TopMost = $true

            $serialLabel = New-Object System.Windows.Forms.Label
            $serialLabel.Text = "Serial Number: $serialOutput`nPIN: $randomPin"
            $serialLabel.AutoSize = $true
        
            $serialPopup.Controls.Add($serialLabel)

            $btnAddKey = New-Object System.Windows.Forms.Button
            $btnAddKey.Text = "Add Key"
            $btnAddKey.Location = New-Object System.Drawing.Point(20, 100)
            $serialPopup.Controls.Add($btnAddKey)

            $btnAddKey.Add_Click({
                Write-Host "Processing $upn with Serial: $serialOutput"

                try {
                    if ($chkSetRandomPin.Checked -and $randomPin) {
                        Write-Host "Setting PIN using fido2-manage.exe..."
                        & ".\fido2-manage.exe" -setPIN -pin $randomPin -device 1
                    }

                    Write-Host "Registering passkey for $upn..."
					 # Set the initial size of the form
$serialPopup.Size = New-Object System.Drawing.Size(900, 100)

# Get the current position of the form
$currentLocation = $serialPopup.Location

# Move the form 300 pixels to the left
$serialPopup.Location = New-Object System.Drawing.Point(($currentLocation.X - 300), $currentLocation.Y)

					 
					 
					 
                    Register-Passkey -UserId $upn -DisplayName $serialOutput
					      $serialPopup.Size = New-Object System.Drawing.Size(400, 200)
					# Define a callback function
				

					 
                    Write-Host "Passkey registered successfully for $upn."
					  

                    $forcedPin = $false
                    if ($chkForcePinChange.Checked -and $randomPin) {
                        Write-Host "Forcing PIN change using fido2-manage.exe..."
                        & ".\fido2-manage.exe" -forcePINchange -pin $randomPin -device 1
                        $forcedPin = $true
                    }

                    # Log the results
                    $logEntry = "$upn,$serialOutput,$randomPin,$forcedPin"
                    if (-not (Test-Path $logFilePath)) {
                        "UPN,Serial Number,PIN,ForcePINChange" | Out-File -FilePath $logFilePath -Encoding UTF8
                    }
                    $logEntry | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    Write-Host "Logged results for $upn."
					  # Show MessageBox only if there's a next user
    if ($currentIndex -lt $totalUsers) {
        [System.Windows.Forms.MessageBox]::Show("Prepare the next key and click OK to continue.", 
            "Next Key Prompt", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information)
    } else {
        Write-Host "All users processed. No further prompts."
    }
	
                } catch {
                    Write-Host "Error during provisioning "
                    [System.Windows.Forms.MessageBox]::Show("An error occurred during provisioning ", "Error")
                } finally {
                    # Close the popup
                    $serialPopup.Close()
                }
            })

            $serialPopup.ShowDialog()
        }

        [System.Windows.Forms.MessageBox]::Show("Provisioning complete.", "Success")
		 $form.Visible = $true
    } catch {
        Write-Host "An error occurred: $($_)"
        [System.Windows.Forms.MessageBox]::Show("An error occurred: $($_)", "Error")
    }
})

 

$form.ShowDialog()


$form.add_Activated({
    [User32]::SetForegroundWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
})
