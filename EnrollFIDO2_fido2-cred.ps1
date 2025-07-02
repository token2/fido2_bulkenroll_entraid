$samplepin = '1234587'


###region utility functions

###taken from https://github.com/rmbolger/Posh-ACME/blob/main/Posh-ACME/Private/ConvertTo-Base64Url.ps1 (MIT, Commit 13367d2)
function ConvertTo-Base64Url {
    [CmdletBinding()]
    [OutputType('System.String')]
    param(
        [Parameter(ParameterSetName='String',Mandatory,Position=0,ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(ParameterSetName='String')]
        [switch]$FromBase64,
        [Parameter(ParameterSetName='Bytes',Mandatory,Position=0)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    Process {
        if (-not $FromBase64) {
            # get a byte array from the input string
            if ($PSCmdlet.ParameterSetName -eq 'String') {
                $Bytes = [Text.Encoding]::UTF8.GetBytes($Text)
            }
            # standard base64 encoder
            $s = [Convert]::ToBase64String($Bytes)
        } else {
            # $Text is already Base64 encoded, we just need the Url'ized version
            $s = $Text
        }
        # remove trailing '='s
        $s = $s.Split('=')[0]
        # 62nd and 63rd char of encoding
        $s = $s.Replace('+','-').Replace('/','_')
        return $s
    }
}

#https://stackoverflow.com/a/10939609 (changed to only allow integers
function Is-Numeric ($Value) {
    return $Value -match "^[\d]+$"
}

# not publicly exported therefore taken unmodified
# from (DS-Internals.Passkeys v1.0.3, MIT) https://github.com/MichaelGrafnetter/webauthn-interop
function Get-MgGraphEndpoint {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    [Microsoft.Graph.PowerShell.Authentication.AuthContext] $context = Get-MgContext -ErrorAction Stop

    if($null -ne $context) {
        return (Get-MgEnvironment -Name $context.Environment -ErrorAction Stop).GraphEndpoint
    }
    else {
        # TODO: PS Error Record ($PSCmdlet.ThrowTerminatingError())
        throw 'Not connected to Microsoft Graph.'
    }
}

###endregion

###region CBOR handling

function cbor-build-len($type, $len){
	if($len -lt 24) { # less than 24 -> into the type byte itself
		return (@($type+$len))
	}
	elseif($len -lt 256) { # more than 24 but within 1 Byte -> Add 24 to type, then add the byte
		$full=@()
		$full+=@($type+24)
		$full+=@($len)
		return $full
	}
	elseif($len -lt 65536) { # 2 bytes -> add 25 and the length bytes individually (Big Endian)
		$full=@()
		$full+=@($type+25)
		$full+=@([int][Math]::Floor($len / 256))
		$full+=@($len%256)
		return $full
	}
	else {
		exit #processing of larger sizes is currently not required
	}
}

function str-to-bytes($str) { #get UTF-8 Byte array for CBOR Text
	return ([system.Text.Encoding]::UTF8.GetBytes($str))
}

function cbor-build-text($str) {
	$typetxt=96
	#get text as UTF-8 Bytes and CBOR Type/length data
	$strarray=str-to-bytes($str)
	$cborlen=cbor-build-len $typetxt $strarray.Count
	$full = @()
	$full += $cborlen 
	$full += $strarray
	return $full
}

function cbor-build-bytes($b64) { #bytes from base64
	$typebytes=64
	$bytearray=[System.Convert]::FromBase64String($b64)
	#get cbor type and length bytes
	$cborlen=cbor-build-len $typebytes $bytearray.Count
	#prepare empty array to add type, length and data
	$full = @()
	$full += $cborlen
	$full += $bytearray
	return $full
}

function build-att-object($sig, $authdata, $x5c, $alg="es256") {
	#cbor base types
	$map=160
	$array=128
	$neg=32
	$ecdsamod=6 #-7 -> in cbor negative = (-1) - argument
	
	if($alg -ne "es256") {
		Exit # Let's not deal with this for now
	}
	
	$cbor= @() #empty array
	Write-Host "preparing CBOR..."
	#map of 3 (format, statement, authdata)
	$cbor += cbor-build-len $map 3
	#fmt:packed
	$cbor += cbor-build-text("fmt")
	$cbor += cbor-build-text("packed")
	#attestation statement map (alg,sig,x5c)
	$cbor += cbor-build-text("attStmt") 
	$cbor += cbor-build-len $map 3
	#alg:-7 (ES256, add more later maybe)
	$cbor += cbor-build-text("alg") 
	$cbor += @(38)
	#attetstation signature
	$cbor += cbor-build-text("sig")
	$cbor += cbor-build-bytes($sig)
	#x5c (attestation cert)
	$cbor += cbor-build-text("x5c")
	#currently no support for Intermediates, therefore a fixed array of 1
	$cbor += cbor-build-len $array 1
	$cbor += cbor-build-bytes($x5c)
	#authdata (already with cbor typing and length data, so can just b64 decode and append, after the label
	$cbor += cbor-build-text("authData")
	$cbor += [System.Convert]::FromBase64String($authdata)
	#convert everything to Base64 for sending out
	$cborb64 = [System.Convert]::ToBase64String($cbor)
	
	return $cborb64
}

###endregion



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


# Function to generate a random PIN (8 digits, PIN+ complexity)
function Generate-RandomPin {
    do {
        # Generate a random 8-digit PIN
        $pin = -join ((48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
        
        # Check for sequential numbers (ascending or descending) of 6 digits
        $isSequential = $false
        for ($i = 0; $i -le ($pin.Length - 6); $i++) {
            $slice = $pin.Substring($i, 6)
            if ('0123456789'.Contains($slice) -or '9876543210'.Contains($slice)) {
                $isSequential = $true
                break
            }
        }

        # Check for repeated digits (4 or more in a row)
        $hasRepeatedDigits = $pin -match '(\d)\1{3,}'

        # Check for palindrome
        $charArray = $pin.ToCharArray()
        [Array]::Reverse($charArray)
        $reversedPin = -join $charArray
        $isPalindrome = ($pin -eq $reversedPin)

    } while ($isSequential -or $hasRepeatedDigits -or $isPalindrome)

    return $pin
}


# taken from Register-Passkey https://github.com/MichaelGrafnetter/webauthn-interop
# (DSInternals.Passkeys v1.0.3, MIT)
# sending finalized Passkey data to API, cut down to only do the sending to API, and relaxed typing of Passkey for easier access
function Graph-Register-Custom-Passkey
{
    [CmdletBinding()]
    [OutputType([Microsoft.Graph.PowerShell.Models.MicrosoftGraphFido2AuthenticationMethod])]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('User')]
        [string] $UserId, #upn
		#json string instead for easier access from outside
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String] $Passkey
    )
    process
    {
		## send finished passkey to API
		[string] $endpoint = Get-MgGraphEndpoint
		# Generate the user-specific URL, e.g., https://graph.microsoft.com/beta/users/af4cf208-16e0-429d-b574-2a09c5f30dea/authentication/fido2Methods
		[string] $registrationUrl = '{0}/beta/users/{1}/authentication/fido2Methods' -f $endpoint, [uri]::EscapeDataString($UserId)
		
		[string] $response = Invoke-MgGraphRequest `
								-Method POST `
								-Uri $registrationUrl `
								-OutputType Json `
								-ContentType 'application/json' `
								-Body $Passkey
								#-Body $Passkey.ToString()

		return [Microsoft.Graph.PowerShell.Models.MicrosoftGraphFido2AuthenticationMethod]::FromJsonString($response)
    }
}

# taken from New-Passkey https://github.com/MichaelGrafnetter/webauthn-interop (DS-Internals.Passkeys v1.0.3, MIT)
# created nearly from Scratch to bypass Windows Hello
function CTAP-Create-Custom-Passkey
{
    [CmdletBinding()]
    [OutputType([DSInternals.Win32.WebAuthn.MicrosoftGraphWebauthnAttestationResponse])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [DSInternals.Win32.WebAuthn.MicrosoftGraphWebauthnCredentialCreationOptions]
        $Options,

        [Parameter(Mandatory = $true)]
        [string] $DisplayName,
		
		[Parameter(Mandatory = $true)]
        [string] $pin
    )

    process
    {
        try {
			
			#get Relying Party ID, user name/ID 
			$rpid = $Options.PublicKeyOptions.RelyingParty.id
			
			$uid = [Convert]::ToBase64String($Options.PublicKeyOptions.User.Id)
			$uname = $Options.PublicKeyOptions.User.Name
			
			
			###region ClientDataJSON/Hash
			
			#template for clientdata, as written in W3C documentation
			$samplejson='
			{"type":"webauthn.create",
			"challenge":"TZxCee-4fMYIDJz_PbvmdfW82WarB4vaevgJpBK_F2w",
			"origin":"https://site.tld",
			"crossOrigin":false
			}'
			$clientdata = ConvertFrom-Json -InputObject $samplejson
			
			$clientdata.origin= "https://" + $rpid
			
			
			#challenge as Base64url, https://www.w3.org/TR/webauthn-2/#dictionary-client-data
			$chlb64url= ConvertTo-Base64Url $Options.PublicKeyOptions.challenge
			
			
			$clientdata.challenge = $chlb64url
			$clientDataJSON = ConvertTo-Json -InputObject $clientdata -Compress
			
			
			#Create clientDataHash, in Base64, https://developers.yubico.com/libfido2/Manuals/fido2-cred.html
			$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
			$clientdatahashraw = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($clientDataJSON))
			$clientdatahash = [Convert]::ToBase64String($clientdatahashraw)
			
			###endregion
			
			
			
			#initialize with base flags (PIN and create, rest if needed)
            $cli="-w $pin -M"

			#create with user Verification (UV)
			$uv = $Options.PublicKeyOptions.AuthenticatorSelection.UserVerificationRequirement
			if( $uv ) {
				$cli = $cli + " -v"
			}
			#create as resident/discoverable credential
			$rk = $Options.PublicKeyOptions.AuthenticatorSelection.RequireResidentKey
			if( $rk ) {
				$cli = $cli + " -r"
			}
			#create with hmac-secret
			$hmac = $Options.PublicKeyOptions.Extensions.HmacCreateSecret
			if( $hmac ) {
				$cli = $cli + " -h"
			}
			#credProtect
			$cp = $Options.PublicKeyOptions.Extensions.CredProtect.value__
			if( Is-Numeric($cp) ) {
				$cli = $cli + " -c " + $cp
			}
			
			#get eligible FIDO Devices, please only have one FIDO Device connected at a time
			$devicelist = (& "$PSScriptRoot\libfido2-ui.exe" -L).Split([Environment]::NewLine)
			
			foreach ($fidodevice in $devicelist) {
				$devicepath=($fidodevice -Split ": ")[0]
				#take first device that is not windows hello.
				if($devicepath -ne "windows://hello") {
					Break
				}
			}
			#add chosen device as final argument
			$cli = $cli + " $devicepath" 
			
			
			#prepare clientDataHash(base64), RPID, Username and user ID(base64) as Inputs for fido2-cred
			$input= $clientdatahash + "`n" + $rpid + "`n" + $uname + "`n" + $uid + "`n"
			
            # Keep the current output encoding in a variable
            $oldEncoding = [console]::OutputEncoding
            # Set the output encoding to use UTF8 without BOM
            [console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

            #modded for nfc and pin, pipe in inputs as UTF-8 to avoid writing unneeded files
            $cred = $input | & ".\fido2-cred2.exe" $cli.split()

            [console]::OutputEncoding = $oldEncoding
			#create array from the outputs and extract authenticator data, signature and attestation certificate (x5c) to manually build attestation object
			$credarray=$cred -Split "`n"
			
			$authdata=$credarray[3]
			$sig=$credarray[5]
			$x5c=$credarray[6]
			$attobj = build-att-object $sig $authdata $x5c "es256"
			
			#pull credential ID as Base64URL to send to Microsoft
			$credid=ConvertTo-Base64Url -FromBase64 $credarray[4]
			
			#Exit
			
			## credential format, sampled from Microsoft Documentation
			$samplejson2=@"
			{
			  "displayName": "Sample",
			  "publicKeyCredential": {
				"id": "pgI",
				"response": {
				  "clientDataJSON": "VGhpcy",
				  "attestationObject": "VGhpcy"
				}
			  }
			}
"@
			#prepare everything for sending to Microsoft
			$send = ConvertFrom-Json -InputObject $samplejson2
			$send.displayName=$DisplayName
			$send.publicKeyCredential.response.clientDataJSON=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($clientDataJSON))
			$send.publicKeyCredential.response.attestationObject=$attobj
			$send.publicKeyCredential.id=$credid
			$sendjson=ConvertTo-Json -InputObject $send
			return $sendjson
        }
        catch {
            throw
        }
    }
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
$defaultValue = "token2.onmicrosoft.com"  # Replace with the default value you want

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
$chkSetRandomPin.Text = "Set Random PIN (otherwise $samplepin will be used)"
$chkSetRandomPin.Width = 300  # Set the width to 200 pixels
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
$lblInstruction.Text = "plug the first user's key before proceeding`n(or use NFC for fewer interactions)"
$lblInstruction.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)
$lblInstruction.AutoSize = $true
$lblInstruction.Location = New-Object System.Drawing.Point(20, 220)
$form.Controls.Add($lblInstruction)

# Define Proceed button logic
$btnProceed = New-Object System.Windows.Forms.Button
$btnProceed.Text = "Proceed"
$btnProceed.Width = 200
$btnProceed.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)
$btnProceed.Location = New-Object System.Drawing.Point(20, 260)  # Adjusted lower than the label
$form.Controls.Add($btnProceed)

         ##################           TESTING         ############################
		 $labelFilePath.Text="$PSScriptRoot\users.csv"


 
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
                    [System.Windows.Forms.MessageBox]::Show("No valid serial number detected.`nSkipping.`nPlease prepare next user's key.", "Error")
                    Write-Host "No valid serial number for $upn. Skipping"
                    continue
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error reading serial number.`nSkipping.`nPlease prepare next user's key.", "Error")
                Write-Host "Error reading serial number for $upn"
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
			else {
				$randomPin = $samplepin
			}

            # Create an intermediate popup for the user
            $serialPopup = New-Object System.Windows.Forms.Form
            $serialPopup.Text = "Add Key for $upn"
            $serialPopup.Size = New-Object System.Drawing.Size(400, 200)
            $serialPopup.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
			 
            #$serialPopup.TopMost = $true

            $serialLabel = New-Object System.Windows.Forms.Label
            $serialLabel.Text = "Serial Number: $serialOutput`nUser: $upn`nPIN: $randomPin"
            $serialLabel.AutoSize = $true
            $serialPopup.Controls.Add($serialLabel)
            
            $infoLabel = New-Object System.Windows.Forms.Label
            $infoLabel.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)
            $infoLabel.Text = "If the Key blinks, touch it at the metal area."
            $infoLabel.Location = New-Object System.Drawing.Point(50, 50)
            $infoLabel.Size = New-Object System.Drawing.Size(400, 50)
            $serialPopup.Controls.Add($infoLabel)

			$infoLabel2 = New-Object System.Windows.Forms.Label
            $infoLabel2.Text = "(Or close this window to skip this user)"
            $infoLabel2.Location = New-Object System.Drawing.Point(0, 130)
            $infoLabel2.Size = New-Object System.Drawing.Size(400, 20)
            $serialPopup.Controls.Add($infoLabel2)

            $btnAddKey = New-Object System.Windows.Forms.Button
            $btnAddKey.Text = "Add Key"
            $btnAddKey.Location = New-Object System.Drawing.Point(20, 100)
            $serialPopup.Controls.Add($btnAddKey)

            $btnAddKey.Add_Click({
                Write-Host "Processing $upn with Serial: $serialOutput"

                try {
                    if ($randomPin) {
                        Write-Host "Setting PIN using fido2-manage.exe..."
                        & ".\fido2-manage.exe" -setPIN -pin $randomPin -device 1
                    }

###NOTE   ------------------------------         Passkey registration

                    Write-Host "Registering passkey for $upn..."
					<#
					#I dont think we need this anymore due to Windows Hello being bypassed
					# Set the initial size of the form
					$serialPopup.Size = New-Object System.Drawing.Size(900, 100)

					# Get the current position of the form
					$currentLocation = $serialPopup.Location

					# Move the form 300 pixels to the left
					$serialPopup.Location = New-Object System.Drawing.Point(($currentLocation.X - 300), $currentLocation.Y)
#>
					
					
                    #Graph-Register-Custom-Passkey -UserId $upn -DisplayName $serialOutput
					# apparently calling Graph register makes it not yet be aware of some types, dont ask me why, PLEASE!
					Get-PasskeyRegistrationOptions -UserId $upn | CTAP-Create-Custom-Passkey -DisplayName $serialOutput -pin $randomPin | Graph-Register-Custom-Passkey -UserId $upn
					
					$serialPopup.Size = New-Object System.Drawing.Size(400, 200)
					 
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
					throw
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
