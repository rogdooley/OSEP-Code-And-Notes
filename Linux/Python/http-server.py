
import http.server
import ssl
import argparse
import logging
from datetime import datetime
import os
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer

class RequestHandler(http.server.BaseHTTPRequestHandler):
    
    def __init__(self, *args, **kwargs):
        self.base_directory = kwargs.pop('base_directory', os.getcwd())
        super().__init__(*args, **kwargs)
    
    # Handle POST requests
    def do_POST(self):
        # Get the content length (size of the data)
        content_length = int(self.headers['Content-Length'])
        
        # Read the POST data
        post_data = self.rfile.read(content_length)
        
        # Check if the data is base64 encoded and less than 4KB
        if content_length < 4096:
            try:
                # Attempt to base64 decode the data
                decoded_data = base64.b64decode(post_data).decode('utf-8')
                # Log the base64 string and its decoded content
                logging.info(f"Received Base64 String: {post_data.decode('utf-8')}")
                logging.info(f"Decoded Data: {decoded_data}")
            except Exception as e:
                # If decoding fails, just log the base64 string
                logging.warning(f"Failed to decode Base64 data: {e}")
                logging.info(f"Received Base64 String: {post_data.decode('utf-8')}")
        else:
            # Log the data without decoding if it's over 4KB
            logging.info(f"Received Data (larger than 4KB): {post_data.decode('utf-8')}")

        # Send a simple response back to the client
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST request processed successfully")

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
