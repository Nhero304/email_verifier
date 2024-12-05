import dns.resolver
import smtplib
import base64
import pickle
import os
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# Function to get OAuth 2.0 credentials for Gmail
def get_oauth_credentials():
    scopes = ['https://www.googleapis.com/auth/gmail.send']
    creds = None

    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', scopes)
            creds = flow.run_local_server(port=0)

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
        return f"MX lookup failed: {e}", False

    if 'google.com' in mx_server:
        return f"{email} is hosted on Gmail (Google Workspace).", 'Gmail'
    elif 'outlook.com' in mx_server or 'office.com' in mx_server:
        return f"{email} is hosted on Outlook (Microsoft 365).", 'Outlook'
    else:
        return f"Could not determine email provider for {email}.", 'Unknown'

# Function to perform SMTP verification for Gmail
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
                return f"The email address {email} exists.", True
            else:
                return f"SMTP response code: {code}. The email address {email} does not exist.", False
    except Exception as e:
        return f"Error during verification for Gmail: {e}", False

# Function to perform SMTP verification for Outlook
def verify_outlook(email, mx_server):
    try:
        with smtplib.SMTP(mx_server) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.mail('nikil@tektreeinc.com')  # Use any valid sender's email
            code, message = server.rcpt(email)
            if code == 250:
                return f"The email address {email} exists.", True
            else:
                return f"SMTP response code: {code}. The email address {email} does not exist.", False
    except Exception as e:
        return f"Error during verification for Outlook: {e}", False
