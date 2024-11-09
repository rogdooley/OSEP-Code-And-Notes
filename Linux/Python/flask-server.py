from flask import Flask, request, send_from_directory, abort
import os
import base64
import logging
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='requests.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Base directory for file serving and directory listing
BASE_DIRECTORY = os.getcwd()

@app.route('/<path:filename>', methods=['GET'])
def serve_file(filename):
    # Serve files from the base directory
    file_path = os.path.join(BASE_DIRECTORY, filename)
    if os.path.isfile(file_path):
        return send_from_directory(BASE_DIRECTORY, filename)
    elif os.path.isdir(file_path):
        return list_directory(file_path)
    else:
        return abort(404, description="File or directory not found.")

@app.route('/', methods=['GET'])
def list_directory(dir_path=BASE_DIRECTORY):
    # Generate and return directory listing as HTML
    try:
        listing = os.listdir(dir_path)
        response = f"<html><body><h2>Directory listing for {dir_path}</h2><ul>"
        for item in listing:
            item_path = os.path.join(dir_path, item)
            if os.path.isdir(item_path):
                item += "/"
            response += f'<li><a href="{item}">{item}</a></li>'
        response += "</ul></body></html>"
        return response
    except Exception as e:
        logging.error(f"Error listing directory: {e}")
        abort(500, description="Error generating directory listing.")

@app.route('/', methods=['POST'])
def log_post_request():
    # Log POST request content
    content_length = request.content_length
    post_data = request.data
    
    if content_length and content_length < 8192:
        try:
            decoded_data = base64.b64decode(post_data).decode('utf-8')
            logging.info(f"Received Base64 String: {post_data.decode('utf-8')}")
            logging.info(f"Decoded Data: {decoded_data}")
        except Exception as e:
            logging.warning(f"Failed to decode Base64 data: {e}")
            logging.info(f"Received Base64 String: {post_data.decode('utf-8')}")
    else:
        logging.info(f"Received Data (larger than 4KB): {post_data.decode('utf-8')}")
    
    return "POST request processed successfully", 200

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Flask HTTP Server to log POST requests with directory listing.')
    parser.add_argument('--port', type=int, default=8080, help='Port number to listen on.')
    parser.add_argument('--dir', type=str, default=BASE_DIRECTORY, help='Base directory to serve files from.')
    args = parser.parse_args()
    
    BASE_DIRECTORY = args.dir
    print(f"Starting Flask server on port {args.port}...")
    print(f"Logging requests to requests.log")
    print(f"Serving files from {BASE_DIRECTORY}")
    
    app.run(host='0.0.0.0', port=args.port)

