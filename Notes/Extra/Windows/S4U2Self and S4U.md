
### Tutorial: Understanding and Exploiting S4U2Self and S4U Abuse Techniques

#### **1. What is S4U2Self?**

S4U2Self (Service-for-User-to-Self) is a part of the Kerberos protocol designed to allow a service (usually running on a Windows Server) to request a Kerberos service ticket on behalf of a user, without requiring the user’s password. This feature is intended to facilitate seamless authentication in environments where multiple services are accessed, particularly for constrained delegation.

In Windows, constrained delegation with protocol transition allows one service to impersonate users to another service under strict conditions. With S4U2Self, the service can generate a ticket for the user on its behalf and use that ticket to access other resources.

#### **2. S4U2Self Workflow**

1. A service requests a Service Ticket to itself for a specified user.
2. The KDC (Key Distribution Center) checks the service's Service Principal Name (SPN) and validates whether it has the necessary permissions.
3. If valid, the KDC sends a Service Ticket back to the service for the requested user.
4. The service can now act on behalf of the user to other services.

### **Why S4U2Self is Vulnerable**

While this protocol is powerful, it has several vulnerabilities that attackers can exploit:

1. **Lack of user interaction**: Since the protocol doesn’t require the user's password, an attacker who controls a service account with delegation rights can request tickets for any user without their credentials.
   
2. **Privilege escalation**: If an attacker can gain control over a service account that has constrained delegation rights, they can impersonate users (even privileged ones like domain administrators) to other services.

3. **Misconfigurations**: In environments where delegation is misconfigured, services might have more power than intended. This could allow attackers to impersonate highly privileged users and compromise sensitive services like the Domain Controller.

---

#### **3. S4U Abuse Techniques**

Let’s explore how attackers exploit the S4U2Self functionality:

### **a) Constrained Delegation Abuse**

Constrained delegation allows a service to impersonate a user to a specific set of services. However, if an attacker gains access to an account with constrained delegation rights, they can abuse this trust to impersonate a user and interact with target services as that user.

##### **Exploit Steps**:

1. **Compromise a service account**: Gain control over an account that has constrained delegation rights, such as a web or file server.
   
2. **Request an S4U2Self ticket**: Use the service’s permissions to request a Kerberos ticket for a target user.

3. **Request an S4U2Proxy ticket**: The S4U2Proxy extension allows a service to request a service ticket on behalf of the user for another service. This enables the attacker to impersonate the user to services they shouldn’t have access to, such as the domain controller.

#### **Tools**:

- **Rubeus**: One of the main tools used for S4U2Self and S4U abuse. Rubeus can request and abuse service tickets, allowing an attacker to impersonate users without needing their passwords.
  
  ```bash
  # Example of requesting an S4U2Self ticket
  Rubeus.exe s4u /user:TARGETUSER /rc4:TARGETUSERHASH /impersonateuser:ADMINUSER /msdsspn:cifs/DC
  ```

  This command leverages S4U2Self to impersonate a domain administrator and request a service ticket for the `cifs` service on the domain controller.

### **b) Unconstrained Delegation Abuse**

In environments where unconstrained delegation is enabled, any account with delegation rights can request a service ticket for any user. This includes sensitive users like domain administrators. If unconstrained delegation is enabled, an attacker with control of such a service account can easily escalate privileges.

##### **Exploit Steps**:

1. **Compromise an account with unconstrained delegation**: This could be any service account or machine with these rights.
   
2. **Obtain a TGT (Ticket Granting Ticket)**: From this account, request a TGT for a highly privileged account, such as a Domain Admin, using the service’s delegation rights.

3. **Abuse the ticket**: Once the attacker has the ticket, they can use it to perform actions as the privileged user.

#### **Tools**:

- **Mimikatz**: A classic tool used for dumping credentials and Kerberos tickets. It can be used to extract Kerberos tickets from memory and inject them into the current session.

  ```bash
  mimikatz "privilege::debug" "sekurlsa::tickets /export" exit
  ```

  This command will dump all the Kerberos tickets on the machine, including any privileged TGTs.

---

### **4. Detecting and Defending Against S4U Abuse**

To mitigate S4U2Self and S4U abuse, it's essential to implement the following defenses:

1. **Restrict delegation rights**: Regularly audit service accounts and ensure that only necessary accounts have delegation rights. Also, avoid giving unconstrained delegation to sensitive accounts.

2. **Implement the principle of least privilege**: Ensure that only necessary services can delegate, and limit their access to critical services.

3. **Monitor service accounts**: Regularly check for unusual activity involving service accounts with constrained or unconstrained delegation rights.

4. **Use event logging**: Enabling detailed Kerberos logging can help detect abuse attempts. Look for unusual service ticket requests that involve privileged accounts.

---

### **Conclusion**

S4U2Self and S4U2Proxy are powerful features within the Kerberos protocol, but their misuse can lead to privilege escalation attacks if not properly secured. Attackers exploiting these features can impersonate users, escalate privileges, and gain access to sensitive resources, especially in environments where delegation is misconfigured.

By understanding how these features work and employing proper monitoring and access control, you can significantly reduce the risk of S4U abuse in your environment. Tools like Rubeus and Mimikatz demonstrate how attackers can leverage these vulnerabilities, but they can also be used to test and secure your systems against such attacks.