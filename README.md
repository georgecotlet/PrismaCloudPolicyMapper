# Prisma Cloud Policy Management

This repository contains three Python scripts designed to manage and update policies in Prisma Cloud, perform policy mapping with AWS Foundational Security Best Practices (FSBP), and send email alerts for policy updates. These scripts interact with both Prisma Cloud and AWS Simple Email Service (SES) to automate various tasks.

## Scripts Overview

1. **`alert_policy_update.py`**  
   Sends a list of policies created or updated in the last 24 hours via email using AWS SES. The 24-hour window is parameterized, so it can be adjusted to different time frames.
   
2. **`policy_mapper.py`**  
   Performs fuzzy matching between Prisma Cloud policies and AWS Foundational Security Best Practices (FSBP) or other frameworks. It maps policies to compliance requirements and sections based on `complianceMetadata` and returns the results in a CSV file.

3. **`policy_updater.py`**  
   Updates Prisma Cloud policies with labels, compliance frameworks, requirements, and sections based on a provided CSV file. It ensures that compliance frameworks, requirements, and sections exist and creates them if necessary.

## Setup Instructions

### Prerequisites

- Python 3.x
- AWS SES credentials for sending emails
- Prisma Cloud API credentials

### Installation

1. **Create Python Virtual Environment**:

```bash
python3 -m virtualenv venv && source venv/bin/activate  
```

2. **Install required packages**:

Install the dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

3. **Environment Variables**:

Create a `.env` file in the root directory of your project. You can copy the `.env.example` file and update it with your own credentials:

```bash
cp .env.example .env
```

Update the `.env` file with your Prisma Cloud API credentials and AWS SES credentials:

```ini
# Prisma Cloud API Credentials
PRISMA_API_URL=<your_prisma_cloud_api_url>
PRISMA_ACCESS_KEY=<your_prisma_access_key>
PRISMA_SECRET_KEY=<your_prisma_secret_key>

# AWS SES Credentials
AWS_DEFAULT_REGION=<your_aws_region>  # e.g., us-east-1
AWS_ACCESS_KEY_ID=<your_aws_access_key_id>
AWS_SECRET_ACCESS_KEY=<your_aws_secret_access_key>

# Email Settings
SENDER_EMAIL=<your_sender_email>
RECIPIENT_EMAIL=<recipient_email_address>
```

### Usage

#### 1. `alert_policy_update.py`

This script sends an email with a list of policies that were created or updated in the last 24 hours (or a parameterized time window).

```bash
python alert_policy_update.py --hours <number_of_hours> --cloud aws --cloud azure
```

`--hours`: Optional. Specifies the time window in days. Default is 1 (24 hours).
`--cloud`: Optional. Choose the CSP of your interest: 'aws', 'azure', 'gcp', 'alibaba_cloud', 'oci'.

#### 2. policy_mapper.py
This script maps Prisma Cloud policies to AWS Foundational Security Best Practices (FSBP) or other frameworks using fuzzy matching and compliance metadata.

```bash
python policy_mapper.py --cloud-type aws --policy-type run --framework-csv-file fsbp.csv --compliance-framework "CUSTOM - AWS Foundational Security Best Practices standard" --output-csv-file matched_policies.csv --threshold 50
```

The output is a CSV file (matched_policies.csv) containing matched policies, compliance requirements, and sections.

#### 3. policy_updater.py
This script updates Prisma Cloud policies based on a CSV input file with the following format:

```csv
policy_name,labels,compliance_framework,compliance_requirement,compliance_section,status
"Policy 1","Label1|Label2","Framework","Requirement","Section",true
```

Run the script as follows:

```bash
python policy_updater.py --debug
```