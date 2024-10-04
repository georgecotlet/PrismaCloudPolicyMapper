import json

# Load the policies from policies.json
def load_policies(json_file):
    with open(json_file, 'r') as file:
        policies = json.load(file)
    return policies

# Print the name of each policy where cloudType is AWS, policySubTypes contains "run", and policyMode is "redlock_default"
def print_aws_run_redlock_policies(policies):
    for policy in policies:
        if (policy.get('cloudType') == 'aws' and
            'run' in policy.get('policySubTypes', []) and
            policy.get('policyMode') == 'redlock_default'):
            print(policy['name'])

# Main function
def main():
    json_file = 'policies.json'  # Replace with the path to your policies.json file
    policies = load_policies(json_file)
    print_aws_run_redlock_policies(policies)

if __name__ == "__main__":
    main()
