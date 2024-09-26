Here’s a **BloodHound query cheat sheet** for both **Active Directory forests** and **single Active Directory domains**. These queries can help you identify attack paths, misconfigurations, and potential security risks.

### General Notes:
- Queries in BloodHound are written using **Cypher**, the query language for Neo4j.
- Adjust the domain and user names in the queries to match your specific environment.
- BloodHound's built-in queries are accessible via the GUI, but custom queries provide more flexibility.

---

### **Basic Queries for a Single AD Domain**

1. **Find all domain admins:**
   ```cypher
   MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN\\Domain Admins"}) RETURN u
   ```

2. **Find all users with local admin rights on any machine:**
   ```cypher
   MATCH (u:User)-[r:AdminTo]->(c:Computer) RETURN u.name, c.name
   ```

3. **Find shortest path to Domain Admins:**
   ```cypher
   MATCH p=shortestPath((n:User {name:"DOMAIN\\User"})-[*1..]->(g:Group {name:"DOMAIN\\Domain Admins"})) RETURN p
   ```

4. **Find users with `GenericWrite` privileges over another object:**
   ```cypher
   MATCH (n)-[r:GenericWrite]->(m) RETURN n.name, type(r), m.name
   ```

5. **Find users with `DCSync` rights (Replicating Directory Changes All):**
   ```cypher
   MATCH (u:User)-[r:AllowedToReplicateChangesAll]->(d:Domain) RETURN u.name, d.name
   ```

6. **Find all machines where a specific user has sessions:**
   ```cypher
   MATCH (u:User {name:"DOMAIN\\User"})-[r:HasSession]->(c:Computer) RETURN u.name, c.name
   ```

7. **Find all computers with unconstrained delegation:**
   ```cypher
   MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
   ```

8. **Find all computers where `Domain Admins` have admin rights:**
   ```cypher
   MATCH (g:Group {name:"DOMAIN\\Domain Admins"})-[r:AdminTo]->(c:Computer) RETURN c.name
   ```

9. **Find all high-privilege users (Domain Admins, Enterprise Admins, etc.):**
   ```cypher
   MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name IN ["DOMAIN\\Domain Admins", "DOMAIN\\Enterprise Admins"] RETURN u.name
   ```

---

### **Queries for AD Forests (Multiple Domains)**

1. **Find domain trusts:**
   ```cypher
   MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d1.name, type(r), d2.name
   ```

2. **Find users with admin rights in other domains:**
   ```cypher
   MATCH (u:User)-[r:AdminTo]->(c:Computer) WHERE c.domain <> u.domain RETURN u.name, c.name, c.domain
   ```

3. **Find domain admins in trusted domains:**
   ```cypher
   MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN\\Domain Admins"})-[r:AdminTo]->(c:Computer) WHERE c.domain <> u.domain RETURN u.name, c.name, c.domain
   ```

4. **Find paths from low-privileged users to Domain Admins in other domains (cross-domain paths):**
   ```cypher
   MATCH p=shortestPath((u:User {name:"DOMAIN\\LowPrivUser"})-[*1..]->(g:Group {name:"TRUSTEDDOMAIN\\Domain Admins"})) RETURN p
   ```

5. **Find all principals (users/computers) with `GenericWrite` rights in another domain:**
   ```cypher
   MATCH (u)-[r:GenericWrite]->(m:Domain) WHERE m.name <> u.domain RETURN u.name, type(r), m.name
   ```

6. **Find all trusts between domains in the forest:**
   ```cypher
   MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d1.name, d2.name
   ```

7. **Find users with `GenericAll` privileges in trusted domains:**
   ```cypher
   MATCH (u)-[r:GenericAll]->(m:Domain) WHERE m.name <> u.domain RETURN u.name, type(r), m.name
   ```

8. **Find users in the `Enterprise Admins` group:**
   ```cypher
   MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"FOREST\\Enterprise Admins"}) RETURN u.name
   ```

---

### **Delegation-Related Queries**

1. **Find all users or computers with unconstrained delegation rights:**
   ```cypher
   MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
   ```

2. **Find all accounts allowed to delegate to specific services (constrained delegation):**
   ```cypher
   MATCH (u:User)-[r:AllowedToDelegate]->(c:Computer) RETURN u.name, c.name
   ```

3. **Find users with `msDS-AllowedToDelegateTo` property set:**
   ```cypher
   MATCH (u:User)-[r:AllowedToDelegate]->(c:Computer) RETURN u.name, c.name
   ```

4. **Find all computers with `msDS-AllowedToActOnBehalfOfOtherIdentity` set (Resource-Based Constrained Delegation):**
   ```cypher
   MATCH (c:Computer)-[:HasAllowedToAct]->(u:User) RETURN c.name, u.name
   ```

---

### **Service Account and Privilege Escalation Queries**

1. **Find all Kerberoastable accounts (accounts with `servicePrincipalName` set):**
   ```cypher
   MATCH (u:User) WHERE u.hasspn=true RETURN u.name
   ```

2. **Find all accounts with `Kerberos delegation` rights (allowed to impersonate):**
   ```cypher
   MATCH (u:User)-[r:AllowedToDelegate]->(m) RETURN u.name, type(r), m.name
   ```

3. **Find all `service accounts` (accounts marked as "sensitive and cannot be delegated"):**
   ```cypher
   MATCH (u:User {sensitive:true}) RETURN u.name
   ```

4. **Find users with `WriteDacl` permissions over an object (potential privilege escalation):**
   ```cypher
   MATCH (u:User)-[r:WriteDacl]->(m) RETURN u.name, m.name
   ```

---

### **Attack Path Queries**

1. **Find shortest paths from a specific user to a domain admin (privilege escalation path):**
   ```cypher
   MATCH p=shortestPath((u:User {name:"DOMAIN\\SpecificUser"})-[*1..]->(g:Group {name:"DOMAIN\\Domain Admins"})) RETURN p
   ```

2. **Find all users with `AdminTo` rights on Domain Controllers:**
   ```cypher
   MATCH (u:User)-[r:AdminTo]->(c:Computer {name:"DOMAIN\\DC"}) RETURN u.name, c.name
   ```

3. **Find all `User` or `Computer` objects with the `GenericAll` permission on another object:**
   ```cypher
   MATCH (u)-[r:GenericAll]->(m) RETURN u.name, type(r), m.name
   ```

---

