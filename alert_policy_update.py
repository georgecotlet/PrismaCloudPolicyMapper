import os
import json
import requests
import boto3
import argparse
from dotenv import load_dotenv
from datetime import datetime, timedelta
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
logger.addHandler(console_handler)

# Load environment variables from .env file
load_dotenv()

# Function to fetch policies
def get_policies(base_url, token):
    url = f"https://{base_url}/v2/policy"
    headers = {"content-type": "application/json; charset=UTF-8", "x-redlock-auth": token}
   
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in get_policies: {err}")
        return None

    response_json = response.json()
    return response_json

# Function to filter policies based on time window and cloud types
def filter_policies(policies, time_window, cloud_types):
    now = datetime.now()
    time_threshold = now - timedelta(hours=time_window)

    created_policies = []
    updated_policies = []

    for policy in policies:
        # Only include policies that match the specified cloud types
        if policy.get('cloudType') in cloud_types:
            created_on = datetime.fromtimestamp(policy['createdOn'] / 1000)
            last_modified_on = datetime.fromtimestamp(policy['lastModifiedOn'] / 1000)

            if created_on >= time_threshold:
                created_policies.append(policy)
            elif last_modified_on >= time_threshold and last_modified_on != created_on:
                updated_policies.append(policy)

    return created_policies, updated_policies

# Function to generate HTML content for the email with a table format
def generate_html_email(created_policies, updated_policies, hours, prisma_cloud_api_url):
    # Replace 'api' with 'app' in the base URL for editing
    prisma_cloud_app_url = prisma_cloud_api_url.replace('api', 'app')
    
    html = f"""
    <html>
    <body>
    <h1>Prisma Cloud Policy Updates</h1>
    
    <h2>Policies Created in the Last {hours} Hours</h2>
    <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
        <thead>
            <tr>
                <th>Policy Name</th>
                <th>Policy ID</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
    """
    
    if not created_policies:
        html += f"""
        <tr>
            <td colspan="3" style="text-align: center;">No policies created in the last {hours} hours.</td>
        </tr>
        """
    else:
        for policy in created_policies:
            policy_id = policy['policyId']
            policy_name = policy['name']
            # Generate edit link
            edit_url = f"https://{prisma_cloud_app_url}/governance/{policy_id}/edit?viewId=default&filters=%7B%7D"
            html += f"""
            <tr>
                <td>{policy_name}</td>
                <td>{policy_id}</td>
                <td><a href="{edit_url}" target="_blank">Edit</a></td>
            </tr>
            """
    
    html += f"""
        </tbody>
    </table>
    
    <h2>Policies Updated in the Last {hours} Hours</h2>
    <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
        <thead>
            <tr>
                <th>Policy Name</th>
                <th>Policy ID</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
    """
    
    if not updated_policies:
        html += f"""
        <tr>
            <td colspan="3" style="text-align: center;">No policies updated in the last {hours} hours.</td>
        </tr>
        """
    else:
        for policy in updated_policies:
            policy_id = policy['policyId']
            policy_name = policy['name']
            # Generate edit link
            edit_url = f"https://{prisma_cloud_app_url}/governance/{policy_id}/edit?viewId=default&filters=%7B%7D"
            html += f"""
            <tr>
                <td>{policy_name}</td>
                <td>{policy_id}</td>
                <td><a href="{edit_url}" target="_blank">Edit</a></td>
            </tr>
            """
    
    html += """
        </tbody>
    </table>
    
    </body>
    </html>
    """

    return html


# Function to send email via AWS SES
def send_email_via_ses(aws_region, aws_access_key_id, aws_secret_access_key, sender, recipient, subject, html_content):
    ses_client = boto3.client(
        'ses',
        region_name=aws_region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    try:
        response = ses_client.send_email(
            Source=sender,
            Destination={'ToAddresses': [recipient]},
            Message={
                'Subject': {'Data': subject},
                'Body': {
                    'Html': {'Data': html_content}
                }
            }
        )
        logger.info(f"Email sent! Message ID: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Error sending email: {e}")


def login_saas(base_url, access_key, secret_key):
    url = f"https://{base_url}/login"
    payload = json.dumps({"username": access_key, "password": secret_key})
    headers = {"content-type": "application/json; charset=UTF-8"}
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except Exception as e:
        logger.info(f"Error in login_saas: {e}")
        return None

    return response.json().get("token")


# Main function
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", help="Time window in hours to filter policies (default: 24 hours)", type=int, default=24, required=True)
    parser.add_argument("--cloud", help="Filter policies by cloud type (can be used multiple times)", action='append', choices=['aws', 'azure', 'gcp', 'alibaba_cloud', 'oci'])
    args = parser.parse_args()

    load_dotenv()
    
    # Load environment variables
    base_url = os.getenv("PRISMA_API_URL")
    token = os.getenv("PRISMA_ACCESS_KEY")
    secret = os.getenv("PRISMA_SECRET_KEY")
    # Load AWS credentials from environment variables
    aws_region = os.getenv("AWS_DEFAULT_REGION")
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    sender_email = os.getenv("SENDER_EMAIL")
    recipient_email = os.getenv("RECIPIENT_EMAIL")

    if not base_url or not token or not secret or not sender_email or not recipient_email or not aws_region or not aws_access_key_id or not aws_secret_access_key:
        logger.error("Environment variables for Prisma Cloud or AWS SES are missing.")
        return

    # Set all cloud types if --cloud is not provided
    cloud_types = args.cloud if args.cloud else ['aws', 'azure', 'gcp', 'alibaba_cloud', 'oci']

    # Fetch policies
    token = login_saas(base_url, token, secret)
    policies = get_policies(base_url, token)
    
    if not policies:
        logger.error("No policies fetched.")
        return

    # Filter policies based on time window and cloud types
    created_policies, updated_policies = filter_policies(policies, args.hours, cloud_types)

    # Generate HTML content
    email_content = generate_html_email(created_policies, updated_policies, args.hours, base_url)

    # Send email via AWS SES
    send_email_via_ses(aws_region, aws_access_key_id, aws_secret_access_key, sender_email, recipient_email, f"Prisma Cloud Policies - Last {args.hours} Hours", email_content)

    logger.info("Script completed successfully.")


if __name__ == "__main__":
    main()
