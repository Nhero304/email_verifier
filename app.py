from flask import FlasK, render_template, request, jsonify
import dns.resolver
import smtplib
import base64
import pickle
import json
import os
from dotenv import load_dotenv  # Import load_dotenv
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello, Vercel!"

if __name__ == "__main__":
    app.run()

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)

# Ensure that necessary environment variables are available
google_client_id = os.getenv("GOOGLE_CLIENT_ID")
google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

# Debugging - Check if variables are loaded correctly
print(f"GOOGLE_CLIENT_ID: {google_client_id}")
print(f"GOOGLE_CLIENT_SECRET: {google_client_secret}")

# Ensure both client ID and client secret are available for Google
if not google_client_id or not google_client_secret:
    raise ValueError("Missing Google OAuth client ID or client secret in the .env file")


# Function to decode base64 and save it as 'credentials.json'
def save_credentials_from_env():
    # Load environment variables
    load_dotenv()

    # Get the base64-encoded string from .env file
    encoded_credentials = os.getenv('ENCODED_CREDENTIALS')

    if encoded_credentials:
        # Decode the base64 string to bytes
        decoded_bytes = base64.b64decode(encoded_credentials)

        # Write the decoded bytes back to 'credentials.json'
        with open('credentials.json', 'wb') as f:
            f.write(decoded_bytes)
    else:
        raise ValueError("No ENCODED_CREDENTIALS found in .env file")
    print(f"encoded_credentials: {encoded_credentials}")


# Function to get OAuth credentials for Gmail
def get_oauth_credentials():
    scopes = ['https://www.googleapis.com/auth/gmail.send']
    creds = None

    # Ensure 'credentials.json' is saved from the .env if not already done
    if not os.path.exists('credentials.json'):
        save_credentials_from_env()

    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            try:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', scopes)
                creds = flow.run_local_server(port=0)
            except Exception as e:
                print(f"Error during OAuth flow: {e}")
                raise

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return creds

# Function to verify if the email is hosted on Gmail or Outlook
def verify_email_provider(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_server = mx_records[0].exchange.to_text()
    except Exception as e:
        return f"MX lookup failed: {e}", None  # Return None if provider is not found

    if 'google.com' in mx_server:
        return 'Gmail', mx_server  # Gmail provider
    elif 'outlook.com' in mx_server or 'office.com' in mx_server:
        return 'Outlook', mx_server  # Outlook provider
    else:
        return 'Unknown', mx_server  # Unknown provider but return MX server for fallback

# Function to perform SMTP verification for Gmail using OAuth credentials
def verify_gmail(email, mx_server):
    try:
        creds = get_oauth_credentials()
        auth_string = f"user={email}\1auth=Bearer {creds.token}\1\1"

        with smtplib.SMTP(mx_server) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.docmd("AUTH", "XOAUTH2 " + base64.b64encode(auth_string.encode()).decode())

            server.mail('nikil@tektreeinc.com')  # Use any valid sender's email
            code, message = server.rcpt(email)
            if code == 250:
                return f"SMTP response code:{code}. The email address {email} exists.", True
            else:
                return f"SMTP response code: {code}. The email address {email} does not exist.", False
    except Exception as e:
        return f"Error during verification for Gmail: {e}", False

# Function to perform SMTP verification for Outlook using SMTP credentials
def verify_outlook(email, mx_server):
    try:
        with smtplib.SMTP(mx_server) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.mail('nikil@tektreeinc.com')  # Use any valid sender's email
            code, message = server.rcpt(email)
            if code == 250:
                return f"SMTP response code: {code}. The email address {email} exists.", True
            else:
                return f"SMTP response code: {code}. The email address {email} does not exist.", False
    except Exception as e:
        return f"Error during verification for Outlook: {e}", False

# Function to handle generic SMTP verification for any domain using credentials from .env
def verify_smtp(email, mx_server):
    try:
        with smtplib.SMTP(mx_server) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.mail('nikil@tektreeinc.com')  # Use any valid sender's email
            code, message = server.rcpt(email)
            if code == 250:
                return f"SMTP response code: {code}. The email address {email} exists.", True
            else:
                return f"SMTP response code: {code}. The email address {email} does not exist.", False
    except Exception as e:
        return f"Error during generic SMTP verification: {e}", False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify-email')
def verify_email():
    email = request.args.get('email')

    # Validate email format
    if "@" not in email or "." not in email.split('@')[1]:
        return jsonify({'result': "Invalid email format."})

    # Verify provider and get MX server information
    provider, mx_server = verify_email_provider(email)

    # If the provider is unknown, proceed with SMTP testing using the MX server
    if provider == 'Unknown' or mx_server is None:
        result, valid = verify_smtp(email, mx_server)
        return jsonify({'result': result, 'valid': valid})

    # If provider is found, verify Gmail or Outlook
    if provider == 'Gmail':
        result, valid = verify_gmail(email, mx_server)
    elif provider == 'Outlook':
        result, valid = verify_outlook(email, mx_server)
    else:
        return jsonify({'result': "Unsupported email provider for verification."})

    # Return the result in a JSON response
    return jsonify({'result': result, 'valid': valid})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
