Compromising Active Directory (AD) forests can be a sophisticated process that involves exploiting trust relationships, misconfigurations, and privilege escalation paths within AD. The following outlines common tactics, techniques, and PowerShell-based examples attackers might use to exploit vulnerabilities in AD forests.

### **1. Understanding Active Directory Trusts**

Before we dive into compromising AD forests, it's important to understand **AD trust relationships**. A trust allows users in one AD domain or forest to access resources in another domain or forest.

- **Intra-Forest Trusts**: Trusts between domains within the same forest (implicitly bidirectional).
- **Inter-Forest Trusts**: Trusts between two separate forests (can be one-way or two-way).

By abusing these trusts, attackers can pivot from one domain or forest to another to gain control over an entire environment.

### **2. Reconnaissance**

Attackers often begin by mapping out the environment to discover domains, trust relationships, and privileges. Here’s how PowerShell can be used for reconnaissance in AD:

#### **Get-ADTrust** – Enumerating Trusts
To identify domain or forest trusts, attackers might use the `Get-ADTrust` cmdlet to gather information about AD trust relationships.

```powershell
Get-ADTrust -Filter *
```

This command retrieves all trusts for the current domain, providing key information such as the type of trust and direction (i.e., one-way or two-way). 

Alternatively, attackers can enumerate trust relationships using **PowerView**, a PowerShell tool for AD enumeration:

```powershell
# Using PowerView to enumerate trusts
Get-NetForestTrust
```

---

### **3. Abuse of Trust Relationships**

Once attackers discover trust relationships, they may try to exploit them by performing attacks such as **SID History Injection** and **Kerberos Ticket Forging**.

#### **a) SID History Injection**

**Security Identifier (SID) History** is an attribute in AD that stores the SIDs of previous accounts when migrating accounts between domains. Attackers can inject SIDs into this attribute to impersonate privileged users.

PowerShell can be used alongside `mimikatz` to inject SID history:

```powershell
# Using mimikatz for SID History Injection
Invoke-Mimikatz -Command '"lsadump::sid /domain:target_domain /sid:source_domain"'
```

Once the SID history is injected, attackers can impersonate users across trust boundaries and escalate privileges across domains or forests.

---

#### **b) Kerberos Ticket Forging (Golden Tickets)**

A **Golden Ticket** attack allows attackers to forge a Ticket Granting Ticket (TGT) and impersonate any user, including domain admins, in the forest. Attackers need the **KRBTGT** hash from the target domain to create a golden ticket.

##### Step 1: Dump the KRBTGT hash

```powershell
# Using mimikatz to dump KRBTGT hash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'
```

##### Step 2: Forge the Golden Ticket

With the KRBTGT hash, attackers can use `mimikatz` to generate a TGT for any user:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:target.com /sid:S-1-5-21-xxxx /krbtgt:<krbtgt_hash> /id:500"'
```

This command forges a TGT for the **Administrator** user in the target domain.

##### Step 3: Pass the Ticket

Once the ticket is created, attackers can inject the TGT into their session:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt <path_to_tgt>"'
```

This attack allows lateral movement within the forest.

---

### **4. Cross-Forest Attacks**

#### **a) Exploiting Unconstrained Delegation**

Unconstrained delegation allows a service account or computer to impersonate any user by obtaining their TGT. Attackers can abuse this to move laterally and compromise resources in trusted forests.

Attackers can find accounts with unconstrained delegation using PowerShell:

```powershell
Get-ADObject -Filter {userAccountControl -band 0x80000} -Properties Name, userAccountControl
```

Once an attacker identifies a system with unconstrained delegation, they can use it to steal TGTs and impersonate users:

```powershell
# Using Rubeus to dump Kerberos tickets from a system with unconstrained delegation
Invoke-Rubeus -Command "dump"
```

---

#### **b) Exploiting Kerberos Delegation (S4U2Self & S4U2Proxy)**

With constrained delegation, attackers can abuse the **S4U2Self** and **S4U2Proxy** extensions of Kerberos to impersonate users in another domain or forest.

##### Example of abusing S4U2Self:

```powershell
Invoke-Rubeus -Command "s4u /user:attacker_account /impersonateuser:Administrator /domain:target_domain"
```

In this example, the attacker impersonates the `Administrator` in the trusted forest and can request service tickets on behalf of the user.

---

### **5. DCSync Attack**

Attackers with replication privileges in the AD forest can perform a **DCSync attack** to extract credentials from the domain, including those of high-value accounts like domain admins and the KRBTGT account.

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:Administrator"'
```

This command requests the password hash for the `Administrator` user from the domain controller using the DCSync replication privileges.

---

### **6. Pivoting Between Domains**

After compromising a domain in a trusted forest, attackers can pivot to other domains. By forging tickets or abusing delegation rights, attackers can authenticate across domains, gaining control over the entire forest.

#### Example of Pivoting with Rubeus (Pass-the-Ticket):

```powershell
# Pass the Kerberos ticket to pivot between domains
Invoke-Rubeus -Command "ptt <path_to_ticket>"
```

By injecting the TGT from one domain, attackers can authenticate to services and resources in the trusted domain or forest.

---

### **7. Mitigations**

Mitigating attacks in AD forests involves hardening trust relationships and monitoring for suspicious activity:

- **Limit delegation**: Constrained delegation should only be applied where absolutely necessary, and unconstrained delegation should be avoided.
- **Monitor for ticket usage**: Regularly audit Kerberos tickets and event logs for unusual ticket-granting service (TGS) requests.
- **Use the principle of least privilege**: Ensure service accounts have minimal access and are monitored for abuse.
- **Implement monitoring tools**: Use tools like **ATA** (Advanced Threat Analytics) or **Azure AD Identity Protection** to detect abnormal account behavior.

---

### **Conclusion**

PowerShell provides attackers with a wide range of options to compromise AD forests by abusing trust relationships, delegation, and Kerberos. Key techniques such as **Golden Ticket** attacks, **SID history abuse**, and **DCSync** can allow attackers to move laterally, escalate privileges, and dominate an entire AD forest if not properly secured.