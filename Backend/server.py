from flask import Flask, request, jsonify
import json
import os

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def receive_scan():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    # Count existing files and increment
    index = 1
    while os.path.exists(f"info_{index}.json"):
        index += 1

    filename = f"info_{index}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"Saved to {filename}")
    return jsonify({"status": "success", "saved_as": filename}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
