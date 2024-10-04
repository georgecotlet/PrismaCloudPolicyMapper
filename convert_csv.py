import csv

def process_csv(input_csv, output_csv):
    with open(input_csv, mode='r') as infile, open(output_csv, mode='w', newline='') as outfile:
        csv_reader = csv.DictReader(infile)
        fieldnames = ['policy_name', 'labels', 'compliance_framework', 'compliance_requirement', 'compliance_section', 'status']
        csv_writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        
        # Write the header
        csv_writer.writeheader()
        
        # Process each row and write to output CSV
        for row in csv_reader:
            output_row = {
                'policy_name': f'"{row["prisma_cloud_policy_name"]}"',
                'labels': '"FSBP"',
                'compliance_framework': '"CUSTOM - AWS Foundational Security Best Practices standard"',
                'compliance_requirement': f'"{row["compliance_requirement"]}"',
                'compliance_section': f'"{row["compliance_section"]}"',
                'status': 'true'
            }
            csv_writer.writerow(output_row)

def main():
    input_csv = 'matched_policies_with_parser.csv'  # Input CSV file path
    output_csv = 'processed_policies_output.csv'    # Output CSV file path
    
    process_csv(input_csv, output_csv)
    print(f"CSV processed and saved to {output_csv}")

if __name__ == '__main__':
    main()
