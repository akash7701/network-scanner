import os
import pandas as pd

def load_cve_database(folder_path):
    cve_data = {}
    print("Loading CVE Database...\n")
    for filename in os.listdir(folder_path):
        if filename.endswith('.csv'):
            try:
                df = pd.read_csv(os.path.join(folder_path, filename), delimiter=';', encoding='ISO-8859-1', on_bad_lines='skip', header=None)

                # Print the column names for debugging
                print(f"Columns in {filename}: {df.columns.tolist()}")

                # Assuming the first column is the service identifier
                for index, row in df.iterrows():
                    service = row[1]  # Adjust based on the actual column structure
                    if service not in cve_data:
                        cve_data[service] = []
                    cve_data[service].append({
                        "id": row[0],  # Assuming the first column is the CVE ID
                        "description": row[1]  # Adjust based on actual content
                    })
                
                print(f"Processed {filename}: {len(df)} entries loaded.\n")

            except pd.errors.ParserError as e:
                print(f"Error reading {filename}: {e}")
            except UnicodeDecodeError as e:
                print(f"Unicode error in {filename}: {e}")
            except KeyError as e:
                print(f"Key error in {filename}: {e}")

    print("CVE Database loading complete.\n")
    return cve_data

def get_cve_count(service_banner, cve_data):
    service = service_banner.split()[0]
    count = len(cve_data.get(service, []))
    return count

if __name__ == "__main__":
    cve_data = load_cve_database('CVE Databases')
    service_banner = "Apache 2.4.29"
    cve_count = get_cve_count(service_banner, cve_data)
    
    print(f"CVE count for '{service_banner}': {cve_count}\n")
    
    if cve_count > 0:
        print(f"Details for '{service_banner}':")
        for cve in cve_data[service_banner.split()[0]]:
            print(f" - {cve['id']}: {cve['description']}")
    else:
        print(f"No CVEs found for '{service_banner}'.")
