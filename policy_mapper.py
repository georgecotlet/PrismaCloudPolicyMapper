import requests
import json
import csv
import os
from dotenv import load_dotenv
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
logger.addHandler(console_handler)

# Load environment variables from .env file
load_dotenv()

# Compliance requirements and sections
compliance_mapping = {
    "Protect": ["Protective services", "Secure network configuration", "Data protection", "Secure access management", "Secure development", "API protection"],
    "Identify": ["Logging", "Inventory"],
    "Detect": ["Detection services"],
    "Recover": ["Resilience"],
    "Respond": ["Forensics", "Response actions"]
}

# Load Prisma Cloud policies from policies.json
def load_prisma_policies(json_file):
    with open(json_file, 'r') as file:
        policies = json.load(file)
    return policies

# Load framework policies from CSV
def load_framework_policies(csv_file):
    with open(csv_file, 'r') as file:
        csv_reader = csv.DictReader(file)
        return list(set([row['name'] for row in csv_reader]))

# Perform fuzzy matching
def match_policies(framework_policies, prisma_policies, threshold=60):
    matched_policies = {}
    unmatched_policies = []

    for framework_policy in framework_policies:
        best_match, score = process.extractOne(framework_policy, [policy['name'] for policy in prisma_policies], scorer=fuzz.token_sort_ratio)
        if score >= threshold:
            matched_policies[framework_policy] = best_match
        else:
            unmatched_policies.append(f'"{framework_policy}"')
    
    return matched_policies, unmatched_policies

# Search complianceMetadata for matching compliance requirement and section
def find_best_compliance_match(compliance_metadata):
    best_compliance_requirement = "Unknown Requirement"
    best_compliance_section = "Unknown Section"
    best_compliance_score = 0

    for metadata in compliance_metadata:
        for requirement, sections in compliance_mapping.items():
            # Perform fuzzy matching on both requirementId and sectionDescription
            for section in sections:
                compliance_score = fuzz.token_sort_ratio(requirement, metadata.get('requirementId', '')) + \
                                   fuzz.token_sort_ratio(section, metadata.get('sectionDescription', ''))

                if compliance_score > best_compliance_score:
                    best_compliance_requirement = requirement
                    best_compliance_section = section
                    best_compliance_score = compliance_score

    return best_compliance_requirement, best_compliance_section

# Map policies to compliance requirement and section using complianceMetadata
def map_to_compliance(matched_policies, prisma_policies):
    compliance_data = []
    
    for framework_policy, prisma_policy_name in matched_policies.items():
        # Find the corresponding Prisma Cloud policy in the full list
        prisma_policy = next((policy for policy in prisma_policies if policy['name'] == prisma_policy_name), None)
        
        if prisma_policy and 'complianceMetadata' in prisma_policy:
            # Extract complianceMetadata and search for the best compliance match
            compliance_requirement, compliance_section = find_best_compliance_match(prisma_policy['complianceMetadata'])
        else:
            compliance_requirement, compliance_section = "Unknown Requirement", "Unknown Section"
        
        # Append the mapped policy data
        compliance_data.append({
            "policy_name": f'"{prisma_policy_name}"',
            "labels": '"FSBP"',
            "compliance_framework": '"AWS Foundational Security Best Practices standard"',
            "compliance_requirement": f'"{compliance_requirement}"',
            "compliance_section": f'"{compliance_section}"',
            "status": "true"
        })
    
    return compliance_data

# Write the results to a CSV file
def write_to_csv(compliance_data, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["policy_name", "labels", "compliance_framework", "compliance_requirement", "compliance_section", "status"])
        writer.writeheader()
        for row in compliance_data:
            writer.writerow(row)

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

def main():   
    load_dotenv()
    
    # File paths
    framework_csv_file = 'fsbp.csv'
    output_csv_file = 'matched_policies.csv'    
    
    # Load environment variables
    base_url = os.getenv("PRISMA_API_URL")
    token = os.getenv("PRISMA_ACCESS_KEY")
    secret = os.getenv("PRISMA_SECRET_KEY")

    if not base_url or not token or not secret:
        logger.error("Environment variables for Prisma Cloud or AWS SES are missing.")
        return

    # Fetch policies
    token = login_saas(base_url, token, secret)
    prisma_policies = get_policies(base_url, token)
    
    # Load policies
    framework_policies = load_framework_policies(framework_csv_file)
    
    # Perform fuzzy matching
    matches, unmatched = match_policies(framework_policies, prisma_policies)

    # Map to compliance requirement and section using complianceMetadata
    compliance_data = map_to_compliance(matches, prisma_policies)

    # Write the compliance data to CSV
    write_to_csv(compliance_data, output_csv_file)

    # Print matched and unmatched policies
    logger.info("\n--- Matched Policies ---")
    for framework_policy, prisma_policy in matches.items():
        logger.info(f'Framework Policy: "{framework_policy}" -> Prisma Cloud Policy: "{prisma_policy}"')
    
    logger.info("\n--- Unmatched Policies ---")
    for policy in unmatched:
        logger.info(f'Framework Policy: {policy} -> No match found')

if __name__ == '__main__':
    main()
