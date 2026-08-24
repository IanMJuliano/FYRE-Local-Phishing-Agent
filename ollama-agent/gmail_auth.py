from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import os.path

SCOPES = ['https://www.googleapis.com/auth/gmail.modify',
          'https://www.googleapis.com/auth/gmail.send']

def authenticate_gmail():

    creds = None

    if os.path.exists('token.json'):
        print("TOKEN FOUND — skipping login")
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    else:
        print("NO TOKEN — starting login flow")

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES
        )
        creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)

    return service


if __name__ == "__main__":
    service = authenticate_gmail()
    print("Gmail authentication successful!")
