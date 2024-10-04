__author__ = "Simon Melotte"

import os
import json
import csv
import requests
import argparse
import logging
from dotenv import load_dotenv

# Create a logger object
logger = logging.getLogger()


def update_policy_from_csv(base_url, token, csv_file_path):
    # Fetch the existing policies
    policies = get_policies(base_url, token)
    
    # Define the policy types that are allowed to update compliance metadata
    allowed_policy_types = ["config", "anomaly", "audit_event"]
    
    # Read the CSV file and update policies accordingly
    with open(csv_file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        
        for row in csv_reader:
            policy_name = row['policy_name'].strip('"')
            csv_labels = row['labels'].strip('"').split('|')  # Split labels using "|" delimiter
            framework = row['compliance_framework'].strip('"')
            requirement_name = row['compliance_requirement'].strip('"')
            section_id = row['compliance_section'].strip('"')
            status = row['status'].lower() == "true"  # Convert status to boolean

            # Find the policy by name in the existing policies
            matching_policy = None
            for policy in policies:
                if policy['name'] == policy_name:
                    matching_policy = policy
                    break
            
            if matching_policy:
                policy_id = matching_policy['policyId']
                
                # Combine existing labels with new labels from CSV
                existing_labels = matching_policy.get('labels', [])
                updated_labels = list(set(existing_labels + csv_labels))  # Ensure no duplicates
                
                # Prepare the updated policy data (without compliance metadata yet)
                updated_policy = {
                    "cloudType": matching_policy['cloudType'],
                    "description": matching_policy['description'],
                    "enabled": status,  # Update policy status from CSV
                    "findingTypes": matching_policy['findingTypes'],
                    "labels": updated_labels,  # Updated labels array
                    "name": matching_policy['name'],
                    "policyType": matching_policy['policyType'],
                    "recommendation": matching_policy['recommendation'],
                    "severity": matching_policy['severity'],
                    "rule": matching_policy['rule'],
                }
                
                # Only update compliance metadata for allowed policy types
                if matching_policy['policyType'] in allowed_policy_types:
                    # Step 1: Ensure compliance framework exists
                    compliance = create_if_not_exists_compliance_framework(base_url, token, framework, framework)
                    if not compliance:
                        logger.error(f"Failed to create or find compliance framework '{framework}' for policy '{policy_name}'.")
                        continue  # Skip to the next row
                    
                    # Step 2: Ensure compliance requirement exists
                    requirement = create_if_not_exists_compliance_requirement(base_url, token, compliance['id'], requirement_name, "Requirement description", section_id)
                    if not requirement:
                        logger.error(f"Failed to create or find compliance requirement '{requirement_name}' for policy '{policy_name}'.")
                        continue  # Skip to the next row
                    
                    # Step 3: Ensure compliance section exists
                    section = create_if_not_exists_compliance_section(base_url, token, requirement['id'], section_id, "Section description")
                    if not section:
                        logger.error(f"Failed to create or find compliance section '{section_id}' for policy '{policy_name}'.")
                        continue  # Skip to the next row
                    
                    # Get existing compliance metadata
                    compliance_metadata = matching_policy.get('complianceMetadata', [])
                    
                    # Check if the section['id'] already exists in compliance metadata
                    section_exists = False
                    for metadata in compliance_metadata:
                        if metadata['sectionId'] == section['sectionId'] and compliance['name'] ==  metadata['standardName'] and requirement['name'] == metadata['requirementName']:
                            section_exists = True
                            break

                    # Add new compliance metadata only if section does not exist
                    if not section_exists:
                        compliance_metadata.append({
                            "complianceId": section['id'],
                            "customAssigned": True,
                            "policyId": policy_id,
                            "requirementDescription": requirement['description'],
                            "requirementId": requirement['requirementId'],
                            "requirementName": requirement['name'],
                            "sectionDescription": section['description'],
                            "sectionId": section['sectionId'],
                            "sectionLabel": section['sectionId'],
                            "standardDescription": compliance['description'],
                            "standardId": compliance['id'],
                            "standardName": compliance['name']
                        })
                    else:
                        logger.info(f"Section '{section['sectionId']}' already exists in compliance metadata for policy '{policy_name}', skipping append.")
                    
                    # Add compliance metadata to the policy if the policyType supports it
                    updated_policy["complianceMetadata"] = compliance_metadata
    
                # Send the PUT request to update the policy
                update_url = f"https://{base_url}/policy/{policy_id}"
                headers = {
                    "Content-Type": "application/json; charset=UTF-8",
                    "Accept": "application/json; charset=UTF-8",
                    "x-redlock-auth": token
                }
                
                try:
                    response = requests.put(update_url, headers=headers, json=updated_policy)
                    response.raise_for_status()
                    logger.info(f"Policy '{policy_name}' updated successfully.")
                except requests.exceptions.RequestException as err:
                    logger.error(f"Failed to update policy '{policy_name}': {err}")
            else:
                logger.error(f"Policy '{policy_name}' not found in existing policies.")


def create_if_not_exists_compliance_section(base_url, token, requirement_id, section_id, section_description):
    # URL to get the list of compliance sections for a requirement
    get_url = f"https://{base_url}/compliance/{requirement_id}/section"
    headers = {
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token
    }

    # Check if the section exists
    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in checking compliance sections for requirement ID {requirement_id}: {err}")
        return None

    section_list = response.json()

    # Check if the compliance section already exists
    for section in section_list:
        if section['sectionId'].lower() == section_id.lower():
            logger.info(f"Compliance section '{section_id}' already exists for requirement ID {requirement_id}.")
            return section  # If it exists, return the section (including its ID)

    # If the section does not exist, create it
    post_url = f"https://{base_url}/compliance/{requirement_id}/section"
    payload = {
        "description": section_description,
        "sectionId": section_id
    }

    headers["Content-Type"] = "application/json"

    try:
        post_response = requests.post(post_url, headers=headers, json=payload)
        post_response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in creating compliance section: {err}")
        return None

    logger.info(f"Compliance section '{section_id}' created successfully.")

    # Fetch the list of sections again to retrieve the new section's details
    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in fetching compliance sections after creation for requirement ID {requirement_id}: {err}")
        return None

    section_list = response.json()

    # Look for the newly created section in the updated list
    for section in section_list:
        if section['sectionId'].lower() == section_id.lower():
            logger.info(f"Found newly created compliance section '{section_id}' with ID: {section['id']}")
            return section  # Return the section details including its ID

    logger.error(f"Failed to find the newly created compliance section '{section_id}'")
    return None


def create_if_not_exists_compliance_requirement(base_url, token, compliance_id, requirement_name, requirement_description, requirement_id):
    # URL to get the list of compliance requirements
    get_url = f"https://{base_url}/compliance/{compliance_id}/requirement"
    headers = {
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token
    }

    # Check if the requirement exists
    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in checking compliance requirements for compliance ID {compliance_id}: {err}")
        return None

    requirement_list = response.json()

    # Check if the compliance requirement already exists
    for requirement in requirement_list:
        if requirement['name'].lower() == requirement_name.lower():
            logger.info(f"Compliance requirement '{requirement_name}' already exists for compliance ID {compliance_id}.")
            return requirement  # If it exists, return the requirement (including its ID)

    # If the requirement does not exist, create it
    post_url = f"https://{base_url}/compliance/{compliance_id}/requirement"
    payload = {
        "description": requirement_description,
        "name": requirement_name,
        "requirementId": requirement_id
    }

    headers["Content-Type"] = "application/json"

    try:
        post_response = requests.post(post_url, headers=headers, json=payload)
        post_response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in creating compliance requirement: {err}")
        return None

    logger.info(f"Compliance requirement '{requirement_name}' created successfully.")

    # Fetch the list of requirements again to retrieve the new requirement's ID
    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in fetching compliance requirements after creation for compliance ID {compliance_id}: {err}")
        return None

    requirement_list = response.json()

    # Look for the newly created requirement in the updated list
    for requirement in requirement_list:
        if requirement['name'].lower() == requirement_name.lower():
            logger.info(f"Found newly created compliance requirement '{requirement_name}' with ID: {requirement['id']}")
            return requirement  # Return the requirement details including its ID

    logger.error(f"Failed to find the newly created compliance requirement '{requirement_name}'")
    return None



def create_if_not_exists_compliance_framework(base_url, token, framework_name, framework_description):
    # URL to get the list of compliance frameworks
    get_url = f"https://{base_url}/compliance"
    headers = {
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token
    }

    # Check if the framework exists
    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in checking compliance frameworks: {err}")
        return None

    compliance_list = response.json()

    # Check if the compliance framework already exists
    for framework in compliance_list:
        if framework['name'].lower() == framework_name.lower():
            logger.info(f"Compliance framework '{framework_name}' already exists.")
            return framework  # If it exists, return the framework (with the ID)

    # If the framework does not exist, create it
    post_url = f"https://{base_url}/compliance"
    payload = {
        "description": framework_description,
        "name": framework_name
    }

    headers["Content-Type"] = "application/json"

    try:
        post_response = requests.post(post_url, headers=headers, json=payload)
        post_response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in creating compliance framework: {err}")
        return None

    logger.info(f"Compliance framework '{framework_name}' created successfully.")

    # Fetch the list of frameworks again to retrieve the new framework's ID
    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()  # Raise error for bad status codes
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in fetching compliance frameworks after creation: {err}")
        return None

    compliance_list = response.json()

    # Look for the newly created framework in the updated list
    for framework in compliance_list:
        if framework['name'].lower() == framework_name.lower():
            logger.info(f"Found newly created compliance framework '{framework_name}' with ID: {framework['id']}")
            return framework  # Return the framework details including its ID

    logger.error(f"Failed to find the newly created compliance framework '{framework_name}'")
    return None


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

    logger.debug(f"Response status code: {response.status_code}")
    logger.debug(f"Response headers: {response.headers}")    
    return response_json


def get_compute_url(base_url, token):
    url = f"https://{base_url}/meta_info"
    headers = {"content-type": "application/json; charset=UTF-8", "Authorization": "Bearer " + token}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        logger.error("Oops! An exception occurred in get_compute_url, ", err)
        return None

    response_json = response.json()
    return response_json.get("twistlockUrl", None)


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


def login_compute(base_url, access_key, secret_key):
    url = f"{base_url}/api/v1/authenticate"

    payload = json.dumps({"username": access_key, "password": secret_key})
    headers = {"content-type": "application/json; charset=UTF-8"}
    response = requests.post(url, headers=headers, data=payload)
    return response.json()["token"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    input_csv_file = 'processed_policies_output.csv'    
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    logging.basicConfig(
        level=logging_level, format="%(asctime)s - %(levelname)s - %(message)s", filename="app.log", filemode="a"
    )

    # Create a console handler
    console_handler = logging.StreamHandler()

    # Add the console handler to the logger
    logger.addHandler(console_handler)

    logger.info("======================= START =======================")
    logger.debug("======================= DEBUG MODE =======================")

    load_dotenv()

    url = os.environ.get("PRISMA_API_URL")
    identity = os.environ.get("PRISMA_ACCESS_KEY")
    secret = os.environ.get("PRISMA_SECRET_KEY")

    if not url or not identity or not secret:
        logger.error("PRISMA_API_URL, PRISMA_ACCESS_KEY, PRISMA_SECRET_KEY variables are not set.")
        return

    token = login_saas(url, identity, secret)
    # compute_url = get_compute_url(url, token)
    # compute_token = login_compute(compute_url, identity, secret)
    # logger.debug(f"Compute url: {compute_url}")

    if token is None:
        logger.error("Unable to authenticate.")
        return    
    
    update_policy_from_csv(url, token, input_csv_file)
    

    logger.info("======================= END =======================")


if __name__ == "__main__":
    main()
