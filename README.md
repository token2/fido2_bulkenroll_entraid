
# FIDO2 Key Registration Tool for Microsoft Entra ID

This tool streamlines the process of registering FIDO2 security keys in **Microsoft Entra ID** by leveraging the FIDO2 Provisioning Graph API. It supports features like setting random PINs, managing keys, and logging results, all through a user-friendly graphical interface.

## Features

- **Entra ID Integration**: Fully supports the FIDO2 Provisioning Graph API for seamless key registration.
- **Random and Custom PINs**: Generate random 6-digit PINs or set custom PINs for FIDO2 keys.
- **Forced PIN Change**: Option to enforce PIN change after provisioning.
- **Clipboard Integration**: Automatically copies generated PINs to the clipboard for quick use.
- **Error Handling**: Provides clear prompts for errors and guides the user to resolve them.
- **Detailed Logging**: Logs all operations in a `.log` file for easy reference. 

## Prerequisites

### Required Hardware
- Compatible **FIDO2.1 key**:
  - Keys with FIDO2.1 Final firmware are required for setting and forcing PIN changes.
  - Serial number retrieval is supported only with the **PIN+ series** keys.

### Required Software
- **PowerShell**: Version 5.1 or later.
- **Modules**: 
  - `Microsoft.Graph`
  - `DSInternals.PassKeys` (The script will automatically install these modules if not already present.)

### Required Files
Ensure the following files are included in the archive:
- `read_serial_t2.exe`: Utility to read the serial number of FIDO keys. 
- `fido2-manage.exe`: Tool to manage FIDO2 keys.

### Input File
A CSV file containing user information. The file must include a column named `UPN` (User Principal Name).

### Permissions
- Run the script as **Administrator** (required due to Windows FIDO2 Native API limitations).
- The Entra account used must have the following **Graph API permissions**:
  - `UserAuthenticationMethod.ReadWrite.All`

### Additional Notes
If your Entra account is FIDO2/Passkey-protected, follow these steps:
1. Log in to an application like Microsoft Teams (even if unlicensed).
2. Choose the option **"Sign in to all your apps"**.
3. This will add your credentials to the session, allowing you to select the logged-in account when running the script.
4. The latest update of `read_serial_t2.exe` also allows you to disable or enable the HID functionality of the key using the `-hid 0` or `-hid 1` option. Please note that HID is used for TOTP functionality with companion apps over USB, so only disable it (`-hid 0`) if you do not intend to use the TOTP feature of the key.. 

## Using the Tool

1. **Run the Script**:
   Execute `EnrollFIDO2.ps1` in PowerShell. Ensure the **execution policy** allows script execution. You can enable this by running:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```
   A graphical interface will appear.

2. **Configure Tenant ID**:
   Enter your **Tenant ID** (e.g., `tenantname.onmicrosoft.com`). The tool will auto-detect the Tenant ID if available in the registry.

3. **Select the Input File**:
   Click "Select File" and choose a valid CSV file containing user UPNs.

4. **Set PIN Options**:
   - **Random PIN**: Generates a random 6-digit PIN for each key.
   - **Copy PIN to Clipboard**: Copies the generated PIN to the clipboard.
   - **Force PIN Change**: Enforces PIN change on the key.

5. **Set Log File Path**:
   Specify where the log file should be saved.

6. **Register Keys**:
   Click "Proceed" to start the registration process. The tool will:
   - Read the FIDO key serial number.
   - Optionally set a random PIN.
   - Register the FIDO key for each user via the Graph API.
   - Log the results.

## Sample Log File

Here is an example of the log file content (formatted as CSV but saved with a `.log` extension to differentiate it from the user list file):

```plaintext
Date: 2024-11-28 12:34:56
------------------------------------------------------------
UPN, Serial Number, PIN, Forced PIN Change
john.doe@domain.com, 1234567890, 789012, Yes
jane.smith@domain.com, 0987654321, 456789, No
------------------------------------------------------------
```

Handle this log file carefully, as it contains sensitive information such as PINs.

## Troubleshooting

- **No Serial Number Detected**: Ensure the FIDO key is connected properly and try again. Only PIN+ series keys support serial number retrieval.
- **Error Connecting to Graph API**: Verify the Tenant ID and ensure the necessary permissions are assigned.
- **Tool Doesn't Launch**: Confirm required modules are installed and run the script with appropriate permissions.

## Contact

For support, please [contact us](https://www.token2.swiss/contact) with: 
- Error messages encountered during operation.
- A copy of the log file (if applicable) for analysis.

---

This project partially licensed under the [MIT License](LICENSE), except the **read_serial_t2.exe** utility.
