from flask import Flask, request, jsonify
import hashlib
import uuid
import random
import pandas as pd
import os

app = Flask(__name__)

users = {}  # in-memory store

# this would all be handled by an external service, this is just a dummy
@app.route("/verify", methods=["POST"])
def verify_user():
    data = request.json
    verification_id = str(uuid.uuid4())
    try:
        personal_info = input("Please provide an image of an identifying document: ")
        
        # this would be read from the image
        identification_number = f"{random.randint(0, 9999999999):010d}"
        
        # this could be a variety of types
        identification_type = "SSN"
        
        # this would be encrypted
        row = {
            "uid": data["uid"],
            "verification_id": verification_id,
            "identification_type": identification_type,
            "identification_number": identification_number
        }
        csv_path = "verification_registry.csv"

        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
        else:
            df = pd.DataFrame(columns=row.keys())

        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
        df.to_csv(csv_path, index=False)

        if personal_info == "fail":
            return jsonify({"uid": data["uid"], "verification_id": "", "status": "FAILED"})
        else:
            return jsonify({"uid": data["uid"], "verification_id": verification_id, "status": "SUCCESS"})
        
    except Exception as e:
        print(f"ERROR: {e}")
        return jsonify({"uid": data["uid"], "verification_id": "", "status": "ERROR"})
        


if __name__ == "__main__":
    app.run(port=9000)