import http.server
import ssl
import argparse
import logging
from datetime import datetime

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # Get content length
        content_length = int(self.headers.get('Content-Length', 0))
        # Read request body
        body = self.rfile.read(content_length).decode('utf-8')
        
        # Log request details
        log_entry = [
            f"----- [{datetime.now()}] -----",
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
        self.wfile.write(b'Request received and logged.')

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
    parser = argparse.ArgumentParser(description='Simple HTTP/HTTPS Server to log POST requests.')
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