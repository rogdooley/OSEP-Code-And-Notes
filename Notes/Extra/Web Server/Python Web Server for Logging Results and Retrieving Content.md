
#### Idea here is to send results back from running shellcode, scripts, database queries, etc... to a central location where results can be logged.

- Thought about this during module 15 regarding the MSSQL due to not wanting to hard code sql statements and used a file initially to read the sql queries.
---

## **Code Implementation**


```python
import http.server
import ssl
import argparse
import logging
from datetime import datetime
import os

class RequestHandler(http.server.BaseHTTPRequestHandler):
    
    def __init__(self, *args, **kwargs):
        self.base_directory = kwargs.pop('base_directory', os.getcwd())
        super().__init__(*args, **kwargs)
    
    # Handle POST requests
    def do_POST(self):
        # Get content length
        content_length = int(self.headers.get('Content-Length', 0))
        # Read request body
        body = self.rfile.read(content_length).decode('utf-8')
        
        # Log request details
        self.log_request_info(body)
        
        # Send response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'POST request received and logged.')

    # Handle GET requests
    def do_GET(self):
        # Log the GET request details (before handling it)
        self.log_request_info()
        
        # Get the path and handle directory listing
        file_path = os.path.join(self.base_directory, self.path.lstrip('/'))
        
        if os.path.isdir(file_path):
            # If it's a directory, list the directory contents
            self.list_directory(file_path)
        elif os.path.isfile(file_path):
            # If it's a file, serve the file
            self.serve_file(file_path)
        else:
            # File or directory not found
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'File or directory not found.')
        
    def list_directory(self, dir_path):
        try:
            # Generate directory listing
            listing = os.listdir(dir_path)
            response = f"<html><body><h2>Directory listing for {dir_path}</h2><ul>"
            for item in listing:
                item_path = os.path.join(dir_path, item)
                if os.path.isdir(item_path):
                    item += "/"
                response += f'<li><a href="{item}">{item}</a></li>'
            response += "</ul></body></html>"
            
            # Send the response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Error generating directory listing.')

    def serve_file(self, file_path):
        try:
            # Open the file and send its contents
            with open(file_path, 'rb') as file:
                content = file.read()
                self.send_response(200)
                self.send_header("Content-type", "application/octet-stream")
                self.end_headers()
                self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Error serving file.')

    def log_request_info(self, body=None):
        log_entry = [
            f"----- [{datetime.now()}] -----",
            f"Client IP: {self.client_address[0]}",
            f"Client Port: {self.client_address[1]}",
            f"Path: {self.path}",
            "Headers:",
            str(self.headers)
        ]
        if body:
            log_entry.append("Body:")
            log_entry.append(body)
        log_entry.append("------------------------------\n")
        logging.info('\n'.join(log_entry))

def run_server(port, use_https, cert_file, key_file, log_file, base_directory):
    # Configure logging
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    server_address = ('', port)
    handler = lambda *args, **kwargs: RequestHandler(*args, base_directory=base_directory, **kwargs)
    httpd = http.server.HTTPServer(server_address, handler)
    
    if use_https:
        if not cert_file or not key_file:
            raise ValueError("HTTPS mode requires cert_file and key_file.")
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            server_side=True,
            certfile=cert_file,
            keyfile=key_file,
            ssl_version=ssl.PROTOCOL_TLS
        )
        protocol = 'HTTPS'
    else:
        protocol = 'HTTP'
    
    print(f"Starting {protocol} server on port {port}...")
    print(f"Logging requests to {log_file}")
    print(f"Serving files from {base_directory}")
    httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple HTTP/HTTPS Server to log POST and GET requests with directory listing.')
    parser.add_argument('--port', type=int, default=8080, help='Port number to listen on.')
    parser.add_argument('--https', action='store_true', help='Enable HTTPS.')
    parser.add_argument('--cert', type=str, help='Path to SSL certificate file.')
    parser.add_argument('--key', type=str, help='Path to SSL key file.')
    parser.add_argument('--log', type=str, default='requests.log', help='Path to log file.')
    parser.add_argument('--dir', type=str, default=os.getcwd(), help='Base directory to serve files from.')
    
    args = parser.parse_args()
    
    try:
        run_server(args.port, args.https, args.cert, args.key, args.log, args.dir)
    except Exception as e:
        print(f"Error: {e}")

```

---

## **Explanation**

- **`RequestHandler` Class**:
  - Inherits from `http.server.BaseHTTPRequestHandler`.
  - Overrides the `do_POST` method to handle POST requests.
  - Reads the request headers and body.
  - Logs the details to a specified log file using Python's `logging` module.
  - Sends a simple acknowledgment response back to the client.

- **`run_server` Function**:
  - Configures logging settings.
  - Sets up the server address and initializes the HTTP server.
  - If HTTPS is enabled, wraps the server socket with SSL using provided certificate and key files.
  - Starts the server and listens indefinitely for incoming requests.

- **`__main__` Block**:
  - Uses `argparse` to parse command-line arguments:
    - `--port`: Specify the port number (default is 8080).
    - `--https`: Enable HTTPS mode.
    - `--cert`: Path to the SSL certificate file (required if HTTPS is enabled).
    - `--key`: Path to the SSL key file (required if HTTPS is enabled).
    - `--log`: Path to the log file where requests will be stored (default is `requests.log`).
  - Calls `run_server` with the parsed arguments.
  - Handles exceptions and prints error messages if any issues occur during server startup.

---

## **Usage Instructions**

### **Prerequisites**

- Python 3.x installed on your system.

### **Generating SSL Certificates (for HTTPS)**

If you want to enable HTTPS, you'll need an SSL certificate and a corresponding key. You can generate a self-signed certificate using `openssl`:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

This command will generate two files:
- `key.pem`: Your private key.
- `cert.pem`: Your self-signed certificate.

### **Running the Server**

#### **HTTP Mode**

To run the server in HTTP mode on port 8080 and log requests to `requests.log`:

```bash
python server.py --port 8080 --log requests.log
```

**Example:**

```bash
python server.py --port 8000
```

#### **HTTPS Mode**

To run the server in HTTPS mode:

```bash
python server.py --port 8443 --https --cert cert.pem --key key.pem --log requests.log
```

**Example:**

```bash
python server.py --port 8443 --https --cert ./cert.pem --key ./key.pem
```

### **Testing the Server**

You can test the server using `curl`:

#### **HTTP Request**

```bash
curl -X POST http://localhost:8080 -d "test data"
```

#### **HTTPS Request**

```bash
curl -k -X POST https://localhost:8443 -d "test data"
```

- The `-k` flag tells `curl` to ignore certificate verification since we're using a self-signed certificate.

### **Checking the Logs**

After making requests, check the `requests.log` file to see the logged details:

**Example log entry:**

```
----- [2024-08-31 12:34:56.789012] -----
Client IP: 127.0.0.1
Client Port: 54321
Path: /
Headers:
Host: localhost:8080
User-Agent: curl/7.68.0
Accept: */*
Content-Length: 9
Content-Type: application/x-www-form-urlencoded

Body:
test data
------------------------------
```

---

## **Notes**

- **Security Consideration:** Be cautious when logging request bodies, especially in production environments, as they may contain sensitive information.
- **Error Handling:** The server includes basic error handling but can be extended to handle more specific cases as needed.
- **Concurrency:** For simplicity, this server handles one request at a time. For handling multiple simultaneous requests, consider using `ThreadingHTTPServer`:

  **Modification:**

  Replace:
  ```python
  httpd = http.server.HTTPServer(server_address, RequestHandler)
  ```
  With:
  ```python
  httpd = http.server.ThreadingHTTPServer(server_address, RequestHandler)
  ```

---

## **Conclusion**

This simple Python web server allows you to easily log all incoming POST requests' details to a file, with support for both HTTP and HTTPS protocols. You can customize the listening port and log file location according to your needs. This setup can be useful for testing, debugging, or monitoring purposes.

## Handling POST and GET requests

### **Updated Python Web Server Code**

```python
import http.server
import ssl
import argparse
import logging
from datetime import datetime
import os

class RequestHandler(http.server.BaseHTTPRequestHandler):
    
    # Handle POST requests
    def do_POST(self):
        # Get content length
        content_length = int(self.headers.get('Content-Length', 0))
        # Read request body
        body = self.rfile.read(content_length).decode('utf-8')
        
        # Log request details
        log_entry = [
            f"----- [POST {datetime.now()}] -----",
            f"Client IP: {self.client_address[0]}",
            f"Client Port: {self.client_address[1]}",
            f"Path: {self.path}",
            "Headers:",
            str(self.headers),
            "Body:",
            body,
            "------------------------------\n"
        ]
        logging.info('\n'.join(log_entry))
        
        # Send response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'POST request received and logged.')
    
    # Handle GET requests
    def do_GET(self):
        # Extract the file path from the URL
        file_path = self.path.lstrip('/')
        
        if os.path.exists(file_path) and os.path.isfile(file_path):
            # Log the GET request
            log_entry = [
                f"----- [GET {datetime.now()}] -----",
                f"Client IP: {self.client_address[0]}",
                f"Client Port: {self.client_address[1]}",
                f"Path: {self.path}",
                "Headers:",
                str(self.headers),
                "------------------------------\n"
            ]
            logging.info('\n'.join(log_entry))
            
            # Read and return the file content
            with open(file_path, 'rb') as file:
                content = file.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(content)
        else:
            # File not found
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'File not found.')

def run_server(port, use_https, cert_file, key_file, log_file):
    # Configure logging
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    server_address = ('', port)
    httpd = http.server.HTTPServer(server_address, RequestHandler)
    
    if use_https:
        if not cert_file or not key_file:
            raise ValueError("HTTPS mode requires cert_file and key_file.")
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            server_side=True,
            certfile=cert_file,
            keyfile=key_file,
            ssl_version=ssl.PROTOCOL_TLS
        )
        protocol = 'HTTPS'
    else:
        protocol = 'HTTP'
    
    print(f"Starting {protocol} server on port {port}...")
    print(f"Logging requests to {log_file}")
    httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple HTTP/HTTPS Server to log POST and GET requests.')
    parser.add_argument('--port', type=int, default=8080, help='Port number to listen on.')
    parser.add_argument('--https', action='store_true', help='Enable HTTPS.')
    parser.add_argument('--cert', type=str, help='Path to SSL certificate file.')
    parser.add_argument('--key', type=str, help='Path to SSL key file.')
    parser.add_argument('--log', type=str, default='requests.log', help='Path to log file.')
    
    args = parser.parse_args()
    
    try:
        run_server(args.port, args.https, args.cert, args.key, args.log)
    except Exception as e:
        print(f"Error: {e}")
```

### **Explanation of Changes**

- **`do_GET` Method**:
  - The `do_GET` method is added to handle GET requests. This method extracts the file path from the request URL, checks if the file exists, and returns the file content if it does.
  - If the file does not exist, a `404 File not found` response is sent back.
  - The request is logged in a similar way to POST requests.

### **Testing the Updated Server**

#### **HTTP GET Request**

To retrieve a file from the server:

```bash
curl http://localhost:8080/path/to/file.txt
```

#### **HTTPS GET Request**

To retrieve a file from the server over HTTPS:

```bash
curl -k https://localhost:8443/path/to/file.txt
```

### **Log Example**

**GET Request Log:**

```
----- [GET 2024-08-31 12:40:12.345678] -----
Client IP: 127.0.0.1
Client Port: 54321
Path: /path/to/file.txt
Headers:
Host: localhost:8080
User-Agent: curl/7.68.0
Accept: */*
------------------------------
```

**POST Request Log:**

```
----- [POST 2024-08-31 12:34:56.789012] -----
Client IP: 127.0.0.1
Client Port: 54321
Path: /
Headers:
Host: localhost:8080
User-Agent: curl/7.68.0
Accept: */*
Content-Length: 9
Content-Type: application/x-www-form-urlencoded

Body:
test data
------------------------------
```

### **Conclusion**

This Python web server can now handle both POST and GET requests, logging all details to a file. It also supports HTTPS traffic if configured with a certificate and key. The server can serve files in response to GET requests and log the request data for POST requests, making it versatile for various testing and monitoring scenarios.


## Sending the requests via command line

Certainly! Below are the commands for both Linux and Windows to base64 encode data and send it via a POST request to the Python server:

### **Linux Command**

You can use `echo`, `base64`, and `curl` to encode the data and send the POST request.

#### **Command**

```bash
echo -n 'your data here' | base64 | curl -X POST -H "Content-Type: text/plain" --data @- http://localhost:8080
```

#### **Explanation:**

- `echo -n 'your data here'`: Outputs the string you want to encode without adding a newline at the end.
- `base64`: Encodes the output from `echo` in base64.
- `curl -X POST -H "Content-Type: text/plain" --data @- http://localhost:8080`:
  - `-X POST`: Specifies the POST method.
  - `-H "Content-Type: text/plain"`: Sets the content type to plain text.
  - `--data @-`: Sends the encoded data as the body of the POST request.
  - `http://localhost:8080`: The URL of your Python server.

#### **Example:**

```bash
echo -n 'Hello, World!' | base64 | curl -X POST -H "Content-Type: text/plain" --data @- http://localhost:8080
```

### **Windows Command**

In Windows, you can use `PowerShell` to base64 encode data and `Invoke-RestMethod` or `curl` to send the POST request.

#### **Command using PowerShell:**

```powershell
$encodedData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("your data here"))
Invoke-RestMethod -Uri "http://localhost:8080" -Method Post -ContentType "text/plain" -Body $encodedData
```

#### **Explanation:**

- `[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("your data here"))`: Encodes the string in base64.
- `Invoke-RestMethod`: Sends an HTTP POST request to the server.
  - `-Uri "http://localhost:8080"`: The URL of your Python server.
  - `-Method Post`: Specifies the POST method.
  - `-ContentType "text/plain"`: Sets the content type to plain text.
  - `-Body $encodedData`: Sends the encoded data as the body of the POST request.

#### **Example:**

```powershell
$encodedData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Hello, World!"))
Invoke-RestMethod -Uri "http://localhost:8080" -Method Post -ContentType "text/plain" -Body $encodedData
```

#### **Alternative Windows Command using `curl`:**

If you have `curl` installed on Windows (available in Windows 10 and later), you can use a command similar to the Linux version:

```powershell
$encodedData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("your data here"))
curl -X POST -H "Content-Type: text/plain" --data $encodedData http://localhost:8080
```

#### **Example:**

```powershell
$encodedData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Hello, World!"))
curl -X POST -H "Content-Type: text/plain" --data $encodedData http://localhost:8080
```

### **Summary**

- **Linux**: Use `echo`, `base64`, and `curl` to encode and send POST requests.
- **Windows**: Use `PowerShell` with `Convert.ToBase64String` and `Invoke-RestMethod` or `curl` to encode and send POST requests.



To modify your Python HTTP server script to base64 decode POST request data that's less than 4KB and log both the base64 string and its decoded content, you'll want to:

1. **Check the size of the incoming POST data**.
2. **Base64 decode the data** if it's less than 4KB.
3. **Log the base64 string and its decoded content**.

Here’s a step-by-step example of how you could implement this:

### **Step 1: Import Necessary Modules**

Ensure that you have the required modules imported at the top of your script:

```python
import base64
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
```

### **Step 2: Modify the POST Handling Method**

Modify the `do_POST` method in your HTTP server class to handle the logic for checking the data size, base64 decoding, and logging.

Here’s an example implementation:

```python
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Get content length (size of the data)
        content_length = int(self.headers['Content-Length'])
        
        # Read the POST data
        post_data = self.rfile.read(content_length)
        
        # Base64 encode the POST data
        base64_data = base64.b64encode(post_data).decode('utf-8')
        
        if content_length < 4096:  # Check if data size is less than 4KB
            try:
                # Base64 decode the data
                decoded_data = base64.b64decode(base64_data).decode('utf-8')

                # Log the base64 string and its decoded content
                logging.info(f"Received Base64 String: {base64_data}")
                logging.info(f"Decoded Data: {decoded_data}")
                
            except Exception as e:
                logging.error(f"Failed to decode Base64 data: {e}")
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid Base64 data")
                return
        
        # Process the request as needed
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST request processed successfully")
```

### **Step 3: Setting Up Logging**

Before handling requests, set up logging to ensure the logs are written appropriately:

```python
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    server_address = ('', 8000)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    logging.info("Starting HTTP server on port 8000...")
    httpd.serve_forever()
```

### **Explanation of the Code:**

1. **`do_POST` Method**:
   - The `do_POST` method handles incoming POST requests.
   - The script reads the content length and POST data from the request.
   - If the data size is less than 4KB, it base64 decodes the data and logs both the original base64 string and its decoded content.

2. **Logging**:
   - The script logs both the base64-encoded string and the decoded content. If an error occurs during decoding, an error message is logged, and a `400 Bad Request` response is sent.

3. **Setup Logging**:
   - `logging.basicConfig` is used to set up logging with a specific format and log level (`INFO` in this case).

### **How to Run the Server:**

To run the server with these changes:

1. Save the script.
2. Run it using Python:
   ```bash
   python3 http-server.py
   ```
3. The server will start listening on the specified port (8000 in this example).

### **Sending POST Requests for Testing:**

You can test the server with a POST request using `curl`:

```bash
curl -X POST http://localhost:8000 -d "Test data"
```

If "Test data" is less than 4KB, it will be logged both as a base64 string and its decoded form.

This approach ensures that you can monitor and inspect smaller payloads in POST requests, which is useful for debugging or auditing purposes.


## Alternative to try for better responsiveness

It seems like you're dealing with a Python HTTP server that becomes unresponsive when files are added or replaced in the filesystem. This can happen due to how the server handles file I/O and caching. Rewriting the server as a Flask app could help mitigate these issues by taking advantage of Flask's robust request handling and better file management capabilities.

### **Step 1: Install Flask**

First, ensure that Flask is installed on your system. You can install it using pip:

```bash
pip install flask
```

### **Step 2: Rewriting the HTTP Server as a Flask App**

Here’s how you can rewrite your HTTP server as a Flask app:

```python
from flask import Flask, request, send_from_directory, jsonify
import os
import base64

app = Flask(__name__)

# Directory to serve files from
FILE_DIRECTORY = '/path/to/your/files'

@app.route('/files/<filename>', methods=['GET'])
def serve_file(filename):
    try:
        # Serve the requested file from the directory
        return send_from_directory(FILE_DIRECTORY, filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        file.save(os.path.join(FILE_DIRECTORY, file.filename))
        return jsonify({"success": True, "filename": file.filename}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decode', methods=['POST'])
def decode_base64():
    try:
        data = request.get_data()
        if len(data) < 4096:  # Check if data size is less than 4KB
            decoded_data = base64.b64decode(data).decode('utf-8')
            return jsonify({"base64": data.decode('utf-8'), "decoded": decoded_data}), 200
        else:
            return jsonify({"base64": data.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
```

### **Explanation of the Flask App:**

1. **Serving Files (`/files/<filename>`)**:
   - The route `/files/<filename>` serves files from a specified directory (`FILE_DIRECTORY`).
   - It uses `send_from_directory` to handle the file serving, which is more robust than manually handling file I/O.

2. **Uploading Files (`/upload`)**:
   - The `/upload` route allows users to upload files to the server.
   - The uploaded file is saved to the `FILE_DIRECTORY`.

3. **Base64 Decoding (`/decode`)**:
   - The `/decode` route handles POST requests containing base64-encoded data.
   - If the data is less than 4KB, it decodes the base64 content and returns both the original and decoded data.

### **Step 3: Running the Flask App**

To run the Flask app:

1. **Save the script** as `app.py` or any other name you prefer.
2. **Run the Flask app** using:

   ```bash
   python app.py
   ```

### **Advantages of Using Flask:**

- **Hot Reloading**: Flask can automatically reload the server when files change if you run it in `debug` mode, which can save you from restarting the server manually.
- **Robust File Handling**: Flask's built-in functions like `send_from_directory` handle file serving more efficiently.
- **Error Handling**: Flask provides better mechanisms for handling errors and generating appropriate HTTP responses.
- **Scalability**: Flask apps are easier to scale and deploy using standard WSGI servers (e.g., Gunicorn) compared to a custom-built HTTP server.

### **Handling Unresponsiveness**

If the server becomes unresponsive, Flask’s built-in development server (`app.run(debug=True)`) is single-threaded by default. For production or heavy use, consider deploying with a WSGI server like Gunicorn, which can handle multiple requests concurrently:

```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

This command runs the Flask app with Gunicorn using 4 worker processes.

