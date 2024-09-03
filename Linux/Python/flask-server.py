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
