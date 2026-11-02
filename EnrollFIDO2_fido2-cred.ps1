#Use -Verbose to specify a loglevel, -1 for no custom messages, 0 is default, 1 means slightly more info at significant steps, 2 is super detailed.
param([Int]$verbose=0)

function Write-Log ($var,$level=0) {
	#Write-Host ("Entering Log Writer")
	#Write-Host $verbose
	#Write-Host $level
	if($level -le $verbose) {
		Write-Host($var)
	}
}

if($verbose -gt 0) {
	Write-Log "running at log level $verbose" $verbose
}
elseif($verbose -eq -1) {
	Write-Log "Suppressing most logs" -1
}

$samplepin = '12345679'


###region utility functions

#Windows doesnt apparently always bring a modern Powershell (even 24H2 comes with PS5.1)
function Test-IsValidJson {
    param (
        [string]$JsonString
    )

    # Quick pre-check to rule out empty strings or basic text
    if ([string]::IsNullOrWhiteSpace($JsonString)) { return $false }
	#$JsonString | Out-Host
    try {
        # -ErrorAction Stop forces PowerShell to jump to the catch block on failure
        $null = ConvertFrom-Json -InputObject $JsonString -ErrorAction Stop
		return $true
    }
    catch {
        return $false
    }
}

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

### https://github.com/rmbolger/Posh-ACME/blob/main/Posh-ACME/Private/ConvertFrom-Base64Url.ps1 and cut down
function ConvertB64From-Base64Url {
    [CmdletBinding()]
    [OutputType('System.String', ParameterSetName='String')]
    [OutputType('System.Byte[]', ParameterSetName='Bytes')]
	[OutputType('System.String', ParameterSetName='base64')]
    param(
        [Parameter(ParameterSetName='Bytes',Mandatory,Position=0,ValueFromPipeline)]
        [Parameter(ParameterSetName='String',Mandatory,Position=0,ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Base64Url,
        [Parameter(ParameterSetName='Bytes',Mandatory)]
        [switch]$AsByteArray
    )

    Process {

        # short circuit on empty strings
        if ($Base64Url -eq [string]::Empty) {
            return [string]::Empty
        }

        # put the standard unsafe characters back
        $s = $Base64Url.Replace('-', '+').Replace('_', '/')

        # put the padding back
        switch ($s.Length % 4) {
            0 { break; }             # no padding needed
            2 { $s += '=='; break; } # two pad chars
            3 { $s += '='; break; }  # one pad char
            default { throw "Invalid Base64Url string" }
        }

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

#type+length info
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
	
	Write-Log "Signature: $sig" 2
	Write-Log "Authenticator Data: $authdata" 2
	Write-Log "Attestation Cert: $x5c" 2
	Write-Log "Algorithm: $alg" 2
	
	$cbor= @() #empty array
	Write-Log "preparing CBOR..."
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

function Get-FidoDevice {
	#get eligible FIDO Devices, please only have one FIDO Device connected at a time
	$devicelist = (& "$PSScriptRoot\libfido2-ui.exe" -L).Split([Environment]::NewLine)
	
	foreach ($fidodevice in $devicelist) {
		$devicepath=($fidodevice -Split ": ")[0]
		#take first device that is not windows hello.
		if($devicepath -ne "windows://hello") {
			return $devicepath
		}
	}
	return ""
}

# Function to check and install a module if not present
function Ensure-Module {
    param (
        [string]$ModuleName,
        [string]$InstallCommand = $ModuleName # Defaults to the same name as the module
    )
    # Check if the module is installed
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Log "Module '$ModuleName' is not installed. Installing..."
        try {
            Install-Module -Name $InstallCommand -Scope CurrentUser -Force -AllowClobber
            Write-Log "Module '$ModuleName' installed successfully."
        } catch {
            Write-Log "Failed to install module '$ModuleName': $_"
        }
    } else {
        Write-Log "Module '$ModuleName' is already installed."
    }
}

# Ensure Connect-MgGraph is installed
Ensure-Module -ModuleName "Microsoft.Graph.Identity.SignIns"

# Ensure dsinternals.passkeys is installed
#Ensure-Module -ModuleName "DSInternals.PassKeys"
#Import-Module -Name "DSInternals.PassKeys"

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
    [OutputType([Boolean])]
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
		#cheap check if we even have a valid json, so MS isnt fed too many 400s
		if( (Test-IsValidJson -JsonString $Passkey) -eq $false) {
		Write-Log "Send Passkey ${UserId}: Invalid JSON, will not send to API"
			Return $false
		}
		$respstatus=0
		## send finished passkey to API
		[string] $endpoint = Get-MgGraphEndpoint
		# Generate the user-specific URL, e.g., https://graph.microsoft.com/beta/users/af4cf208-16e0-429d-b574-2a09c5f30dea/authentication/fido2Methods
		[string] $registrationUrl = '{0}/beta/users/{1}/authentication/fido2Methods' -f $endpoint, [uri]::EscapeDataString($UserId)
		
		[string] $response = Invoke-MgGraphRequest `
								-StatusCodeVariable respstatus `
								-Method POST `
								-Uri $registrationUrl `
								-OutputType Json `
								-ContentType 'application/json' `
								-Body $Passkey
								#-Body $Passkey.ToString()
		if( $respstatus -eq 201 ) {
			return $true
		}
		else {
			return $false
		}
		# not actually used, evaluating status code is easier
		#return [Microsoft.Graph.PowerShell.Models.MicrosoftGraphFido2AuthenticationMethod]::FromJsonString($response)
    }
}

# taken from New-Passkey https://github.com/MichaelGrafnetter/webauthn-interop (DS-Internals.Passkeys v1.0.3, MIT)
# created nearly from Scratch to bypass Windows Hello
function CTAP-Create-Custom-Passkey
{
    [CmdletBinding()]
    [OutputType([String])] #JSON of API body
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphWebauthnCredentialCreationOptions]
        $GraphOptions,

        [Parameter(Mandatory = $true)]
        [string] $DisplayName,
		
		[Parameter(Mandatory = $true)]
        [string] $pin,
		
		[Parameter(Mandatory = $true)]
        [string] $devicepath
    )

    process
    {
		Write-Log "CTAP Building: Init" 2
        try {
			$Options = $GraphOptions.PublicKey
			
			#extract options
			
			Write-Log "CTAP Building: Extract Options" 2
			#Return
			Write-Log $Options 2
			
			#get Relying Party ID, user name/ID 
			$rpid = $Options.rp.id
			Write-Log "CTAP Building: rpid: $rpid" 2
			Write-Log $Options.User.Id
			#$uid = [Convert]::ToBase64String($Options.User.Id)
			$uid = ConvertB64From-Base64Url($Options.user.id)
			$uname = $Options.user.name
			Write-Log "Options Collected" 2
			
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
			$chlb64url= ConvertB64From-Base64Url $Options.challenge
			
			
			$clientdata.challenge = $chlb64url
			$clientDataJSON = ConvertTo-Json -InputObject $clientdata -Compress
			Write-Log "ClientDataJson Collected" 1
			Write-Log $clientDataJSON 2
			
			#Create clientDataHash, in Base64, https://developers.yubico.com/libfido2/Manuals/fido2-cred.html
			$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
			$clientdatahashraw = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($clientDataJSON))
			$clientdatahash = [Convert]::ToBase64String($clientdatahashraw)
			Write-Log "ClientDataJson hashed" 2
			###endregion
			
			
			Write-Log "Creating CLI args" 1
			#initialize with base flags (PIN and create, rest if needed)
            $cli="-w $pin -M"
			Write-Log "Added PIN" 2
			#create with user Verification (UV)
			$uv = $Options.authenticatorSelection.userVerification
			if( $uv -eq "required" ) {
				$cli = $cli + " -v"
			}
			Write-Log "added UV requirement" 2
			#create as resident/discoverable credential
			$rk = $Options.authenticatorSelection.requireResidentKey
			if( $rk ) {
				$cli = $cli + " -r"
			}
			#create with hmac-secret
			$hmac = $Options.extensions.hmacCreateSecret
			if( $hmac ) {
				$cli = $cli + " -h"
			}
			Write-Log "Added hmac-secret and RK requirement" 2
			#credProtect
			$cp = $Options.extensions.credProtect
			switch($cp) {
				"userVerificationOptional" {$cp=1}
				"userVerificationOptionalWithCredentialIDList" {$cp=2}
				"userVerificationRequired" {$cp=3}
				default {$cp = $false }
			}
			
			if( Is-Numeric($cp) ) {
				$cli = $cli + " -c " + $cp
			}
			Write-Log "Added credProtect" 2
			
			#add chosen device as final argument
			$cli = $cli + " $devicepath" 
			Write-Log "Using Device path $devicepath" 2
			
			#prepare clientDataHash(base64), RPID, Username and user ID(base64) as Inputs for fido2-cred
			$input = $clientdatahash + "`n" + $rpid + "`n" + $uname + "`n" + $uid + "`n"
			Write-Log $input 1
			
			Write-Log $cli 1
            # Keep the current output encoding in a variable
            $oldEncoding = [console]::OutputEncoding
            # Set the output encoding to use UTF8 without BOM
            [console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

            #modded for nfc and pin, pipe in inputs as UTF-8 to avoid writing unneeded files
            $cred = $input | & "$PSScriptRoot\fido2-cred2.exe" $cli.split()

            [console]::OutputEncoding = $oldEncoding
			
			if([string]::IsNullOrWhiteSpace($cred)) { #check for fail, exit early
				Return $false
			}
			Write-Log "Credential creation on FIDO-Device successful"
			#create array from the outputs and extract authenticator data, signature and attestation certificate (x5c) to manually build attestation object
			$credarray=$cred -Split "`n"
			
			$authdata=$credarray[3]
			$sig=$credarray[5]
			$x5c=$credarray[6]
			
			Write-Log "Building Attestation object..." 1
			$attobj = build-att-object $sig $authdata $x5c "es256"
			
			#pull credential ID as Base64URL to send to Microsoft
			$credid=ConvertTo-Base64Url -FromBase64 $credarray[4]
			Write-Log "Collected data from attested credential"
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
			$sendjson=ConvertTo-Json -InputObject $send -compress
			
			Write-Log "Object to send to MS: $sendjson" 2
			return $sendjson
        }
        catch {
            Return $false
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

###### MAIN START

#Write-Log "test" 0
#Exit


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
    Write-Log "Property '$propertyName' created with value: $defaultValue"
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
        Write-Log "Failed to retrieve Tenant ID from registry: $_" 1
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

# Add a checkbox for "Quick Mode"
#$checkBoxQuickMode = New-Object System.Windows.Forms.CheckBox
#$checkBoxQuickMode.Text = "Quick Mode (fewer individual confirmations)"
#$checkBoxQuickMode.AutoSize = $true
#$checkBoxQuickMode.Location = New-Object System.Drawing.Point(20, 140) # Adjust as needed

#$form.Controls.Add($checkBoxQuickMode)


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
    Write-Log "Checking entered data"
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
		Write-Log "Connecting to MSGraph"
		try {
        Connect-MgGraph -Scopes 'UserAuthenticationMethod.ReadWrite.All,UserAuthMethod-Passkey.ReadWrite.All' -TenantId $tenantId -NoWelcome -ea Stop
		}
		catch{}

        $upns = Import-Csv $filePath | Select-Object -ExpandProperty UPN
		$totalUsers = $upns.Count
		$currentIndex = 0
        :users foreach ($upn in $upns) {
			Write-Log "Starting for $upn"
            if (-not $upn) { continue }
			    $currentIndex++
            # Fetch the serial number using read_serial_t2.ps1
            try {
				:getfidodevice while ($true) {
					
					$device = Get-FidoDevice
					
					if([string]::IsNullOrWhiteSpace($device)) {
						$errorres=[System.Windows.Forms.MessageBox]::Show("No FIDO-Device found.
Please ensure a FIDO2-enabled device is plugged into USB or connected to an NFC or chip reader.", "Error",2)
						if($errorres -eq [System.Windows.Forms.DialogResult]::Abort) {
							#$form.Close()
							break users
						}
						elseif($errorres -eq [System.Windows.Forms.DialogResult]::Retry) {
							continue
						}
						elseif($errorres -eq [System.Windows.Forms.DialogResult]::Ignore) {
							continue users
						}
						Return
					}
					
					Write-Log "Using device $device `n" 1
					
					$deviceinfo = & "$PSScriptRoot\libfido2-ui.exe" -I $device
					
					$nopin = Select-String -InputObject $deviceinfo -Pattern "noclientPin" -CaseSensitive
					
					if([string]::IsNullOrWhiteSpace($nopin)) {
						$errorres=[System.Windows.Forms.MessageBox]::Show("FIDO2-Device has PIN set or does not use PIN:
1) Please make sure the device is reset
2) Please only use FIDO2-Devices that support clientPin
Ignore: try next User, Retry: Retry same User, Abort: Stop everything", "Error",2)
						if($errorres -eq [System.Windows.Forms.DialogResult]::Abort) {
							#$form.Close()
							break users
						}
						elseif($errorres -eq [System.Windows.Forms.DialogResult]::Retry) {
							continue
						}
						elseif($errorres -eq [System.Windows.Forms.DialogResult]::Ignore) {
							continue users
						}
						Return
					}
					
					$serialOutput = (& "$PSScriptRoot\read_serial_t2.ps1")
					#$serialOutput = "12345" ### Debug or for use with non-Token2 Devices
					#$serialOutput = "" ### Debug or for use with non-Token2 Devices
					
					if ([string]::IsNullOrWhiteSpace($serialOutput) -or $serialOutput -eq "None") {
						$errorres=[System.Windows.Forms.MessageBox]::Show("No Serial Number found:
1) This script only works with TOKEN2 PIN+ Release 3 and newer
2) The CCID application (PGP/PIV) needs to be active
3) for older TOKEN2 PIN+ Models, change the script to use read_serial_t2.exe instead
4) for non-TOKEN2-Devices, remove or change the Serial number detection logic
Ignore: try next User, Retry: Retry same User, Abort: Stop everything", "Error",2)
						if($errorres -eq [System.Windows.Forms.DialogResult]::Abort) {
							#$form.Close()
							break users
						}
						elseif($errorres -eq [System.Windows.Forms.DialogResult]::Retry) {
							continue
						}
						elseif($errorres -eq [System.Windows.Forms.DialogResult]::Ignore) {
							continue users
						}
					}
					$serialOutput=$serialOutput.Trim()
					break
				}  ### :getfidodevice
            } catch {
                [System.Windows.Forms.MessageBox]::Show("General error in Device or Serial Number detection.`nPlease open an issue, this should not occur.`nSkipping.`nPlease prepare next user's key.", "Error")
                Write-Log^ "General Exception reading serial number or Device state for $upn"
                continue
            }

            $randomPin = $null
            if ($chkSetRandomPin.Checked) {
                $randomPin = Generate-RandomPin
				Write-Log "Using random PIN $randomPin"
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
                Write-Log "Processing $upn with Serial: $serialOutput"

                try {
					:regisration while($true) { #loop to allow retry
						if ($randomPin) {
							Write-Log "Setting PIN using fido2-token..."
							#& "$PSScriptRoot\fido2-manage.exe" -setPIN -pin $randomPin -device 1
							& "$PSScriptRoot\libfido2-ui.exe" -S -P $randomPin $device
						}

	###NOTE   ------------------------------         Passkey registration

						Write-Log "Registering Credential for $upn..."
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
						Write-Log "Pulling Registration Request for $upn" 1
						try {
							$regreq = Invoke-MgCreationUserAuthenticationFido2MethodOption -UserId $upn -ea Stop
						}
						catch {
							Write-Log "Exception while getting request. (See Error MsgBox)" #User-side Handling below
						}
						if($regreq) {
							$regres = CTAP-Create-Custom-Passkey -DisplayName $serialOutput -pin $randomPin -GraphOptions $regreq -devicepath $device
						}
						else {
							$errorres=[System.Windows.Forms.MessageBox]::Show("Cannot obtain Request from Entra, please verify that:
1) you are logged in to the correct tenant with the correct permissions
2) the tenant ID (domain) is set correctly
3) The UPN is correct
4) You are elevating using your own account
Ignore: try next User, Retry: Retry same User, Abort: Stop everything", "Error",2)
							if($errorres -eq [System.Windows.Forms.DialogResult]::Abort) {
								#$form.Close()
								$serialPopup.DialogResult = [System.Windows.Forms.DialogResult]::Abort
								$serialPopup.Close()
							}
							elseif($errorres -eq [System.Windows.Forms.DialogResult]::Retry) {
								$serialPopup.Close()
								continue;
							}
							elseif($errorres -eq [System.Windows.Forms.DialogResult]::Ignore) {
								$serialPopup.Close()
								break;
							}
							Return
						}
						if($regres) {
							$uploadres=Graph-Register-Custom-Passkey -UserId $upn -Passkey $regres
						}
						else {
							$errorres=[System.Windows.Forms.MessageBox]::Show("Creating Credential failed, please check console Output for common errors: 
FIDO_ERR_RX: Commonication Error, e.g. Device removed.
FIDO_ERR_USER_ACTION_TIMEOUT: User Presence was not given (on USB, please touch or press the button when blinking)
FIDO_ERR_PIN_INVALID: Wrong PIN (Please reset the device, this application assumes `"fresh`" devices)
Ignore: try next User, Retry: Retry same User, Abort: Stop everything", "Error",2)
							if($errorres -eq [System.Windows.Forms.DialogResult]::Abort) {
								#$form.Close()
								$serialPopup.DialogResult = [System.Windows.Forms.DialogResult]::Abort
								$serialPopup.Close()
							}
							elseif($errorres -eq [System.Windows.Forms.DialogResult]::Retry) {
								$serialPopup.Close()
								continue;
							}
							elseif($errorres -eq [System.Windows.Forms.DialogResult]::Ignore) {
								$serialPopup.Close()
								break;
							}
							Return
						}
						if($uploadres) {
							Write-Log "Upload Result: $uploadres" 1
						}
						
						$serialPopup.Size = New-Object System.Drawing.Size(400, 200)
						 
						Write-Log "Passkey registered successfully for $upn."
						  

						$forcedPin = $false
						if ($chkForcePinChange.Checked -and $randomPin) {
							Write-Log "Forcing PIN change using fido2-token..."
							& "$PSScriptRoot\libfido2-ui.exe" -w $randomPin -S -f $device
							$forcedPin = $true
						}

						# Log the results
						$logEntry = "$upn,$serialOutput,$randomPin,$forcedPin"
						if (-not (Test-Path $logFilePath)) {
							"UPN,Serial Number,PIN,ForcePINChange" | Out-File -FilePath $logFilePath -Encoding UTF8
						}
						$logEntry | Out-File -FilePath $logFilePath -Append -Encoding UTF8
						Write-Log "Logged results for $upn."
						  # Show MessageBox only if there's a next user
						if ($currentIndex -lt $totalUsers) {
							[System.Windows.Forms.MessageBox]::Show("Prepare the next key and click OK to continue.", 
								"Next Key Prompt", 
								[System.Windows.Forms.MessageBoxButtons]::OK, 
								[System.Windows.Forms.MessageBoxIcon]::Information)
						} else {
							Write-Log "All users processed. No further prompts."
						}
						break #break out of while($true)-loop
					}
                } catch {
					# I hope we no longer enter here
					Write-Log "An error occurred (registration): $($_)"
                    Write-Log "Error during provisioning"
                    [System.Windows.Forms.MessageBox]::Show("An error occurred during provisioning ", "Error")
					throw
                } finally {
                    # Close the popup
                    $serialPopup.Close()
                }
            })

			# Catch Error State
            $windowres=$serialPopup.ShowDialog()
			if ($windowres -eq [System.Windows.Forms.DialogResult]::Abort) {
				# break out if likely global error
				$notcomplete=$true
				break
			}
        }
		if($notcomplete -ne $true) {
			[System.Windows.Forms.MessageBox]::Show("Provisioning complete.", "Success")
		}
		 $form.Visible = $true
    } catch {
        Write-Log "An error occurred (user cycle): $($_)"
        [System.Windows.Forms.MessageBox]::Show("An error occurred: $($_)", "Error")
    }
})

 

$form.ShowDialog()


$form.add_Activated({
    [User32]::SetForegroundWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
})
