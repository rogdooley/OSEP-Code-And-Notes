
To run the SMB signing check on remote servers, you can use PowerShell's `Invoke-Command` cmdlet, which allows you to execute commands on remote machines. This approach requires that PowerShell Remoting is enabled on the target servers.

Here's how you can adapt the script to check SMB signing on remote servers:

### **Step 1: Enable PowerShell Remoting (if not already enabled)**
Before running the commands, ensure that PowerShell Remoting is enabled on the remote servers. You can enable it by running the following command on each remote server:

```powershell
Enable-PSRemoting -Force
```

### **Step 2: Modify the Script to Run on Remote Servers**

You can use the following PowerShell script to check SMB signing on multiple remote servers:

```powershell
# Function to check SMB signing status on a remote server
function Get-SmbSigningStatusRemote {
    param (
        [string]$ComputerName
    )
    
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $clientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -ErrorAction SilentlyContinue
        $serverSigningRequired = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -ErrorAction SilentlyContinue
        $serverSigningEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name EnableSecuritySignature -ErrorAction SilentlyContinue

        $result = [PSCustomObject]@{
            SMBClientSigningRequired = if ($clientSigning.RequireSecuritySignature -eq 1) { "True" } else { "False" }
            SMBServerSigningRequired = if ($serverSigningRequired.RequireSecuritySignature -eq 1) { "True" } else { "False" }
            SMBServerSigningEnabled  = if ($serverSigningEnabled.EnableSecuritySignature -eq 1) { "True" } else { "False" }
            ComputerName             = $env:COMPUTERNAME
        }

        return $result
    }
}

# List of remote servers to check
$servers = @("Server1", "Server2", "Server3")  # Replace with your server names

# Run the check on each server
$results = $servers | ForEach-Object { Get-SmbSigningStatusRemote -ComputerName $_ }

# Display the results
$results | Format-Table -AutoSize
```

### **Step 3: Run the Script**

1. **Save the script** as a `.ps1` file (e.g., `Check-SmbSigningRemote.ps1`).
2. **Run the script** from a machine that has network access to the target servers.

### **Explanation of the Script**:

- **Invoke-Command**: Runs the SMB signing check on the remote servers specified in the `$servers` array.
- **ComputerName**: The name of the remote server is passed to the `-ComputerName` parameter of `Invoke-Command`.
- **ScriptBlock**: Contains the original script logic to check SMB signing, but it now runs on the remote server.
- **Results**: The script collects the SMB signing status from each server and displays them in a table.

### **Sample Output**:

The script will output the SMB signing status for each server in a formatted table:

```plaintext
SMBClientSigningRequired SMBServerSigningRequired SMBServerSigningEnabled ComputerName
------------------------ ------------------------ ----------------------- -------------
True                     True                     True                    Server1      
False                    True                     False                   Server2      
True                     True                     True                    Server3      
```

### **Considerations**:

- **Permissions**: Ensure that you have administrative privileges on the remote servers to query the registry.
- **PowerShell Remoting**: If PowerShell Remoting is not enabled or allowed by firewall rules, you'll need to enable it or use other methods (e.g., WinRM, DCOM) to run commands remotely.
- **Firewall**: Ensure that the firewall allows inbound traffic on the necessary ports for PowerShell Remoting (default is TCP 5985 for HTTP and 5986 for HTTPS).

This script allows you to efficiently check the SMB signing configuration on multiple remote servers, helping you to ensure that SMB communication is secured across your network.


If you don't have PowerShell Remoting access to a remote server but still need to check if SMB signing is enforced, there are alternative methods you can use. These methods primarily involve checking the registry settings or using command-line tools like `psexec` or remote registry access.

### **Method 1: Use `psexec` to Check SMB Signing Remotely**

`psexec` is a tool from the Sysinternals suite that allows you to execute commands on remote systems. You can use it to remotely query the registry for SMB signing settings.

#### **Steps**:

1. **Download and Install Sysinternals**:
   - Download the Sysinternals Suite from [Microsoft's website](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) if you don't already have it.

2. **Use `psexec` to Query the Registry**:
   - Run the following commands to check the SMB signing settings on a remote server.

```cmd
psexec \\RemoteServerName reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v RequireSecuritySignature
psexec \\RemoteServerName reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v RequireSecuritySignature
psexec \\RemoteServerName reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v EnableSecuritySignature
```

- **Output**:
  - **RequireSecuritySignature**:
    - If the value is `1`, SMB signing is required.
    - If the value is `0`, SMB signing is not required.
  - **EnableSecuritySignature**:
    - If the value is `1`, SMB signing is enabled but not necessarily enforced.
    - If the value is `0`, SMB signing is disabled.

### **Method 2: Use Remote Registry Access**

If you have access to the remote registry (even without PowerShell Remoting), you can check the SMB signing settings.

#### **Steps**:

1. **Enable Remote Registry Service** (if necessary):
   - Ensure the "Remote Registry" service is running on the remote server. This service allows you to connect to and manage the registry of the remote machine.

2. **Access the Remote Registry**:
   - Open `regedit.exe` on your local machine.
   - Go to `File` > `Connect Network Registry...`.
   - Enter the name of the remote server.

3. **Navigate to the Registry Paths**:
   - **SMB Server**:
     - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
   - **SMB Client**:
     - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`

4. **Check the Values**:
   - Look for the `RequireSecuritySignature` and `EnableSecuritySignature` values.
   - The meaning of these values is the same as described in the previous methods.

### **Method 3: Use `sc.exe` or `netsh` for Checking Firewall Rules**

Even without direct access, you might be able to check whether SMB signing is enforced by examining network policies or firewall rules.

#### **Steps**:

1. **Check if SMB Signing Enforcement via Policies**:
   - You can attempt to use `sc.exe` to check if the SMB-related services (e.g., `LanmanServer`) are configured in a way that suggests SMB signing enforcement.

   ```cmd
   sc \\RemoteServerName qc LanmanServer
   ```

2. **Check SMB Traffic Requirements via `netsh`**:
   - You can use `netsh` to list firewall rules related to SMB traffic on the remote server. While this doesn’t directly tell you about SMB signing, it can indicate how tightly the traffic is controlled.

```cmd
   psexec \\RemoteServerName netsh advfirewall firewall show rule name=all
```

Yes, you can check the SMB signing settings on Windows servers from a Linux machine by querying the SMB protocol directly using tools like `smbclient` and `rpcclient`, which are part of the Samba suite. These tools allow you to interact with SMB servers and can help determine whether SMB signing is required or enabled.

### **Method 1: Using `smbclient`**

`smbclient` can be used to query the SMB signing status of a Windows server.

#### **Steps**:

1. **Install Samba**:
   - If you don't have `smbclient` installed, you can install it using your package manager.
     ```bash
     sudo apt-get install smbclient  # For Debian/Ubuntu-based systems
     sudo yum install samba-client   # For Red Hat/CentOS-based systems
     ```

2. **Check SMB Signing**:
   - Run the following command to check the SMB signing status on a Windows server:
     ```bash
     smbclient -L //WindowsServerName -U username -m SMB3
     ```

   - **Interpret the Results**:
     - If SMB signing is required, you'll see a message like:
       ```plaintext
       protocol negotiation failed: NT_STATUS_ACCESS_DENIED
       ```
     - If SMB signing is enabled but not required, you might be able to list the shares without enforcing signing.
     - If SMB signing is disabled, you'll be able to connect and list the shares without any errors related to signing.

### **Method 2: Using `rpcclient`**

`rpcclient` can query various aspects of a Windows server, including SMB-related configurations.

#### **Steps**:

1. **Install Samba**:
   - Ensure `rpcclient` is installed (part of the Samba suite).

2. **Check SMB Signing**:
   - Run the following command to check SMB signing:
     ```bash
     rpcclient -U username -c 'lsaquery' WindowsServerName
     ```

   - **Interpret the Results**:
     - If SMB signing is required, `rpcclient` might fail to connect, or you might receive a specific status message indicating SMB signing is enforced.
     - If SMB signing is not required, the command should succeed and return information about the server.

### **Method 3: Use Nmap with the SMB Script**

`nmap` includes scripts that can check SMB settings on a Windows server, including whether SMB signing is required.

#### **Steps**:

1. **Install Nmap**:
   - If `nmap` isn't installed, install it using your package manager:
     ```bash
     sudo apt-get install nmap
     ```

2. **Run Nmap with SMB Scripts**:
   - Use `nmap` with the `smb-security-mode` script to check the SMB signing status:
     ```bash
     nmap --script smb-security-mode -p 445 WindowsServerName
     ```

   - **Interpret the Results**:
     - The output will indicate whether SMB signing is enabled and/or required on the target server. You'll see something like:
       ```plaintext
       | smb-security-mode: 
       |   account_used: guest
       |   authentication_level: user
       |   challenge_response: supported
       |   message_signing: required
       |   message_signing: supported
       ```

### **Automating the Check for Multiple Windows Servers**

If you want to check multiple Windows servers, you can write a simple bash script that iterates over a list of server names or IP addresses and uses one of the methods above to check each one.

#### **Example Bash Script**:

```bash
#!/bin/bash

# List of Windows servers
servers=("Server1" "Server2" "Server3")

# Loop through each server
for server in "${servers[@]}"
do
    echo "Checking SMB signing on $server..."
    smbclient -L //$server -U your_username -m SMB3 2>&1 | grep 'NT_STATUS_ACCESS_DENIED'
    if [ $? -eq 0 ]; then
        echo "$server: SMB signing is required."
    else
        echo "$server: SMB signing is not required or is disabled."
    fi
done
```

- **Explanation**:
  - Replace `your_username` with a valid username that has access to the Windows servers.
  - The script will check each server and print whether SMB signing is required or not based on the presence of the `NT_STATUS_ACCESS_DENIED` error.

### **Conclusion**
By using tools like `smbclient`, `rpcclient`, and `nmap`, you can remotely check the SMB signing status on Windows servers from a Linux machine. These methods allow you to assess the security configuration of SMB on your Windows servers without needing PowerShell Remoting access.

`netexec` (formerly known as CrackMapExec) is a powerful tool commonly used for post-exploitation and lateral movement in Windows environments. It includes modules for SMB and other protocols, and can help you assess SMB signing on remote Windows servers.

### **Using netexec to Check SMB Signing**

`netexec` can directly check SMB signing settings on a remote server. Here's how you can do it:

#### **Step 1: Install netexec**

If you don't have `netexec` installed, you can install it from the GitHub repository. It's typically installed within a Python virtual environment:

```bash
# Clone the repository
git clone https://github.com/byt3bl33d3r/CrackMapExec.git netexec

# Change to the netexec directory
cd netexec

# Install the required dependencies
pip install -r requirements.txt

# Install netexec
python setup.py install
```

#### **Step 2: Check SMB Signing on a Single Server**

You can use `netexec` to check the SMB signing status on a specific Windows server using the `smb` module.

```bash
netexec smb <IP or hostname> --shares
```

- **Interpret the Results**:
  - If SMB signing is required, `netexec` will indicate that signing is enforced in the output.
  - If SMB signing is enabled but not required, `netexec` will indicate that signing is supported but not mandatory.
  - If SMB signing is disabled, `netexec` will connect without requiring signing.

#### **Step 3: Check SMB Signing Across Multiple Servers**

If you have multiple servers to check, you can specify them in a text file and pass it to `netexec`.

```bash
netexec smb --targets targets.txt --shares
```

- **Interpret the Results**:
  - The output will show the SMB signing status for each server listed in `targets.txt`.

#### **Step 4: Example Command to Check SMB Signing**

Here’s a specific example command:

```bash
netexec smb 192.168.1.100 --shares
```

- **Expected Output**:
  - You will see output similar to the following, which will indicate the SMB signing status:
    ```plaintext
    SMB         192.168.1.100 445    SERVER_NAME  Signing: REQUIRED (or DISABLED or SUPPORTED)
    ```

- **Key Points**:
  - **Signing: REQUIRED**: Indicates that SMB signing is enforced on the server.
  - **Signing: SUPPORTED**: Indicates that SMB signing is supported but not enforced.
  - **Signing: DISABLED**: Indicates that SMB signing is disabled.

### **Automating SMB Signing Checks with netexec**

You can write a simple bash script to check SMB signing on a list of servers:

```bash
#!/bin/bash

# List of servers to check
servers=("192.168.1.100" "192.168.1.101" "192.168.1.102")

# Loop through each server and check SMB signing
for server in "${servers[@]}"
do
    echo "Checking SMB signing on $server..."
    netexec smb $server --shares | grep "Signing"
done
```

- **Explanation**:
  - This script iterates over the list of servers, runs `netexec` against each, and greps for the "Signing" status to determine if SMB signing is required, supported, or disabled.

### **Conclusion**

`netexec` provides a straightforward way to check SMB signing settings on Windows servers from a Linux machine. It can be used to assess SMB security configurations across multiple servers, making it a valuable tool for penetration testers and security professionals.