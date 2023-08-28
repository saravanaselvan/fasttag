from __future__ import print_function

import os.path
import re

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
import csv

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def parse_pattern(pattern, text):
    return re.findall(pattern, text)
def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', q=f"from:fastag@hdfcbank.net subject:Toll after:2023/8/10").execute()
        messages = results.get('messages', [])

        toll_fees = []

        for message in reversed(messages):
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            msg_data = msg['payload']['headers']
            date = [item['value'] for item in msg_data if item['name'] == 'Date'][0]

            decoded_msg_body = ""
            if 'data' in msg['payload']['body']:
                msg_body = msg['payload']['body']['data']
                decoded_msg_body = base64.urlsafe_b64decode(msg_body).decode('utf-8')
            else:
                msg_parts = msg['payload']['parts']
                for part in msg_parts:
                    if part['mimeType'] == 'text/plain' or part['mimeType'] == 'text/html':
                        msg_body = part['body']['data']
                        decoded_msg_body = base64.urlsafe_b64decode(msg_body).decode('utf-8')
                        break

            matches = parse_pattern(r"Plaza:\s*.*? ", decoded_msg_body)
            location = ""
            fee = ""
            for match in matches:
                location = match.split(":")[1].split("<br>")[0].strip()

            matches = parse_pattern(r'Rs\.\s*\d+\s', decoded_msg_body)

            for match in matches:
                fee = match.split(".")[1].strip()

            toll_fee = {"Date": date, "Location": location, "Fee": fee}
            toll_fees.append(toll_fee)

        csv_file_path = 'toll_fees.csv'

        with open(csv_file_path, mode='w', newline='') as file:
            fieldnames = toll_fees[0].keys()
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()

            for row in toll_fees:
                writer.writerow(row)

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()