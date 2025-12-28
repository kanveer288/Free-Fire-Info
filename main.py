from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import asyncio

# Assuming this module exists and works as intended.
# You will need to make sure this path is correct for your local setup.
import app.utils.res_data as res_data

app = Flask(__name__)
CORS(app)

# 1. NEW ROUTE: This handles the root path ('/') and prevents the 404 error
@app.route('/')
def home():
    """Returns a simple HTML message confirming the server is running and instructs the user on how to use the API."""
    return """
    <div style="font-family: Arial, sans-serif; padding: 20px; text-align: center;">
        <h1 style="color: #4CAF50;">✅ Flask Server Running</h1>
        <p>This server is designed to provide information via the <code>/info</code> endpoint.</p>
        <p>To view the API output, please use the following format in your browser:</p>
        <code style="background-color: #f0f0f0; padding: 5px 10px; border-radius: 5px; display: inline-block;">
            http://127.0.0.1:3000/info?uid=<strong>[YOUR_UID_HERE]</strong>
        </code>
        <p style="margin-top: 20px; font-size: 0.9em; color: #777;">
            Replace <strong>[YOUR_UID_HERE]</strong> with the actual user ID you wish to query.
        </p>
    </div>
    """

# 2. YOUR ORIGINAL ROUTE (with a small improvement for testing)
@app.route('/info')
def get_account_info():
    uid = request.args.get('uid')

    if not uid:
        # Suggestion: For a 400 Bad Request, return a simple explanation or a suggested format.
        response = {
            "error": "Invalid request",
            "message": "Empty 'uid' parameter. Please provide a valid 'uid' in the URL query string, e.g., /info?uid=123456"
        }
        return jsonify(response), 400, {'Content-Type': 'application/json; charset=utf-8'}

    try:
        # Run the asynchronous data retrieval function
        # NOTE: This only works because this is running inside the main thread of Flask
        return_data = asyncio.run(res_data.GetAccountInformation(uid, "7","/GetPlayerPersonalShow"))
        
        # Format the JSON for readability in the browser
        formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
        
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
    
    except Exception as e:
        # Catch errors from the external data function gracefully
        error_response = {
            "error": "Internal Server Error",
            "message": f"An error occurred while fetching data for UID: {uid}. Details: {str(e)}"
        }
        return jsonify(error_response), 500, {'Content-Type': 'application/json; charset=utf-8'}


if __name__ == '__main__':
    # Flask will automatically use the updated code because debug=True
    app.run(port=3000, host='0.0.0.0', debug=True)
