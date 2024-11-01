import os
import secrets
from dotenv import load_dotenv
from pymongo import MongoClient
import boto3
import hashlib
import certifi
from openai import OpenAI
import requests
from flask import Flask, render_template, jsonify, request
import re
from pymongo import errors
import redis
from apscheduler.schedulers.background import BackgroundScheduler

# Set SSL_CERT_FILE environment variable
os.environ['SSL_CERT_FILE'] = certifi.where()

load_dotenv()  # Load environment variables from .env file
applications = []
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB max file size

# Configure your OpenAI API key
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)
# MongoDB configuration
mongo_uri = os.getenv("MONGO_URI")
mongo_client = MongoClient(mongo_uri, tlsCAFile=certifi.where(), tlsAllowInvalidCertificates=True)
db = mongo_client['pdf']
collection_chat = db['chat']
collection_history = db['history']

# Redis configuration
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = os.getenv("REDIS_PORT", 6379)
redis_db = redis.StrictRedis(host=redis_host, port=redis_port, decode_responses=True)

# Boto S3 Client creation
def create_s3_client(access_key, secret_key, region_name):
    return boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region_name
    )

# MD5 calculation
def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

# S3 file download
def download_file_from_s3(s3_client, bucket_name, s3_file_key, local_file_path):
    s3_client.download_file(bucket_name, s3_file_key, local_file_path)

# Redis insertion
def insert_or_update_md5(file_name, md5_checksum, last_processed_position=0):
    redis_db.hset(file_name, mapping={"md5": md5_checksum, "position": last_processed_position})

# Fetch stored MD5
def get_stored_md5(file_name):
    stored_data = redis_db.hgetall(file_name)
    if stored_data:
        return stored_data.get("md5"), int(stored_data.get("position", 0))
    return None, 0

# Log file analysis
def analyze_log_file(file_content, s3_file_key):
    user_query = "Identify vulnerabilities like XSS and SQL Injections in the log file"

    # Prompt to LLM
    prompt = f"""
        Given the following log file content, identify any vulnerabilities like XSS and SQL Injections, and provide the results in the format of MongoDB fields as shown below:
        Dont return in JSON format:\n\n{file_content}\n\nUser Query: {user_query}\n\nAnswer the user's query in the mongodb key:value foramt.Please dont give any extra information.

         Format:(consider this as example)
            machine: machine_name,
            threat_detected: true/false,
            content: Detected attack description,
            threat_details: 
                type: XSS/SQLInjection,
                description: Description of the attack,
                risk_level: high/low,
                recommendation: Mitigation recommendation,
                example_payload: Example attack payload,
                timestamp: 2023-10-09T00:13:37.197+00:00
            
            
           Please provide the result in this exact format.
        """
    
    try:
        # Request completion from LLM
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            model="gpt-3.5-turbo",
        )

        result = response.choices[0].message.content.strip()

        # Process the result to handle multiple threats
        
        log_pattern = r'\[(.*?)\] \[(.*?)\] (.*? from IP \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        matches = re.findall(log_pattern, file_content)
        
        for match in matches:
            timestamp = match[0]
            log_level = match[1]
            message = match[2]
            
            threat_detected = False
            threat_type = ""
            description = ""
            risk_level = "low"
            recommendation = "N/A"
            example_payload = "N/A"

            if "SQL Injection attempt detected" in message or "Possible SQL Injection" in message:
                threat_detected = True
                threat_type = "SQLInjection"
                description = "Detected SQL Injection attempt"
                risk_level = "high"
                recommendation = "Implement input validation and parameterized queries"
                example_payload = re.search(r'URL: (.*)', message).group(1) if "URL:" in message else "N/A"
                
            elif "XSS attack detected" in message:
                threat_detected = True
                threat_type = "XSS"
                description = "Detected XSS attack"
                risk_level = "high"
                recommendation = "Implement input validation and output encoding"
                example_payload = re.search(r'on (.*)', message).group(1) if "on " in message else "N/A"
            
            if threat_detected:
                threat_details = {
                    "type": threat_type,
                    "description": description,
                    "risk_level": risk_level,
                    "recommendation": recommendation,
                    "example_payload": example_payload,
                    "timestamp": timestamp
                }

                document = {
                    "machine": "Unknown",
                    "threat_detected": threat_detected,
                    "content": description,
                    "threat_details": threat_details
                }

                # Insert document into MongoDB collection
                try:
                    collection_chat.insert_one(document)
                except errors.PyMongoError as mongo_error:
                    print(f"MongoDB insertion error: {mongo_error}")

        return "Threats inserted successfully"

    except Exception as e:
        print(f"Error processing and inserting threats: {e}")
        return f"Error: {e}"

# Compare and print changes
def compare_and_print_changes(file_name, new_md5, s3_file_key):
    stored_md5, last_processed_position = get_stored_md5(file_name)
    
    if stored_md5 != new_md5:
        print("File has been modified.")
        with open(file_name, 'r') as f:
            f.seek(last_processed_position)
            new_content = f.read()
            print(new_content)
            analysis_results = analyze_log_file(new_content, s3_file_key)
            print("Vulnerability Analysis Results:")
            print(analysis_results)
            
            current_position = f.tell()
        
        insert_or_update_md5(file_name, new_md5, current_position)
    else:
        print("File has not been modified.")

# Background task to check for new machines and process logs
def check_new_machines():
    while True:
        for application in applications:
            try:
                s3_client = create_s3_client(application['aws_access_key_id'], application['aws_secret_access_key'], application['aws-default-region'])
                local_file_path = os.path.join(os.getcwd(), application['application_logs_path'])
                download_file_from_s3(s3_client, application['bucket_name'], application['application_logs_path'], local_file_path)
                
                new_md5 = calculate_md5(local_file_path)
                compare_and_print_changes(local_file_path, new_md5, application['application_logs_path'])
            except Exception as e:
                print(f"Error processing logs for {application['name']}: {e}")

# Endpoint to add new machine
@app.route('/add_machine', methods=['POST'])
def add_machine():
    try:
        new_machines = request.json
        if isinstance(new_machines, list):
            for machine in new_machines:
                applications.append(machine)
            return jsonify({"message": "Machines added successfully"}), 201
        else:
            return jsonify({"error": "Invalid format, expected a list"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Start background task
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_new_machines, trigger="interval", seconds=6, max_instances=3)
scheduler.start()

if __name__ == "__main__":
    app.run(debug=True)