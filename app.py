from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime
from functools import wraps

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
uri = os.getenv("MONGO_URI")
secret_key = os.getenv("SECRET_KEY_JWT")

# Create a new MongoDB client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Access database and collection
db = client["ExpenseTracking"]
users_collection = db["Users"]
expenses_collection = db["Expenses"] 
# API: Sign-Up
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        # Check if the user already exists
        if users_collection.find_one({"username": username}):
            return jsonify({"error": "User already exists"}), 400

        # Hash the password using Werkzeug
        hashed_password = generate_password_hash(password)

        # Store user in the database
        users_collection.insert_one({
            "username": username,
            "password": hashed_password,  # Store the hashed password
        })

        # Generate JWT token
        token = jwt.encode(
            {"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            secret_key,
            algorithm="HS256"
        )

        return jsonify({"message": "User created successfully", "token": token}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API: Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        # Find the user in the database
        user = users_collection.find_one({"username": username})
        if not user:
            return jsonify({"error": "Invalid username or password"}), 401

        # Check if the password matches
        if not check_password_hash(user['password'], password):
            return jsonify({"error": "Invalid username or password"}), 401

        # Generate JWT token
        token = jwt.encode(
            {"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            secret_key,
            algorithm="HS256"
        )

        return jsonify({"message": "Login successful", "token": token}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Decorator for JWT token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check if the token is provided in the request headers
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Bearer <token>

        if not token:
            return jsonify({"error": "Token is missing!"}), 401

        try:
            # Decode the token using the secret key
            decoded_data = jwt.decode(token, secret_key, algorithms=["HS256"])
            request.user = decoded_data  # Attach the decoded data (e.g., username) to the request object
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token!"}), 401

        return f(*args, **kwargs)
    return decorated


# API: Add New Expense
@app.route('/add_expense', methods=['POST'])
@token_required
def add_expense():
    try:
        # Get user info from decoded JWT
        user_data = request.user
        username = user_data.get("username")

        # Get expense details from request body
        data = request.json
        expense_name = data.get("expense_name")
        expense_category = data.get("expense_category")
        date = data.get("date")  # Expected in ISO format (e.g., 2025-01-16)
        amount = data.get("amount")

        # Validate input
        if not all([expense_name, expense_category, date, amount]):
            return jsonify({"error": "All fields (expense_name, expense_category, date, amount) are required"}), 400

        if not isinstance(amount, (int, float)) or amount <= 0:
            return jsonify({"error": "Amount must be a positive number"}), 400

        # Create expense document
        expense = {
            "username": username,
            "expense_name": expense_name,
            "expense_category": expense_category,
            "date": date,
            "amount": amount,
            "created_at": datetime.datetime.utcnow()  # Timestamp
        }

        # Insert expense into the database
        expenses_collection.insert_one(expense)

        return jsonify({"message": "Expense added successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
