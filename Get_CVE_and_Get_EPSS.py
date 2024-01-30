import pandas as pd
import requests

# Function that will be used to accept a list of CVEs
def get_epss_scores(cve_list):
    base_url = "https://api.first.org/data/v1/epss"
    scores = {}

    # loop que itera sobre cada CVE na lista 'cve_list' e armazena o identificar CVE
    for cve_id in cve_list:
        try:
            # loop that iterates over each CVE in the 'cve_list' and stores the CVE identifier
            response = requests.get(base_url, params={"cve": cve_id})
            response.raise_for_status()
            data = response.json()
            if 'data' in data and len(data['data']) > 0:
                scores[cve_id] = data['data'][0]['epss']
            else:
                scores[cve_id] = "No score to EPSS to CVE analised."
        except requests.RequestException as e:
            scores[cve_id] = f"Error: {e}"

    return scores

# Loading the CSV file and extracting CVEs
file_path = '/dir/cve-file.csv'
df = pd.read_csv(file_path)

# Set to store all unique CVEs
unique_cves_set = set()

# Search for the word CVE + Regex in the file
if 'CVEs' in df.columns:
    cve_data = df['CVEs'].dropna()
    cve_pattern_with_group = r'(CVE-\d{4}-\d{4,7})'
    # Extract the identified CVE
    cves_extracted = cve_data.str.extractall(cve_pattern_with_group)[0]

    # Iterates over the extracted CVEs and does not save duplicates
    for cve in cves_extracted:
        unique_cves_set.add(cve)

    # Converts the content with all CVEs into a list for easier handling
    unique_cves_list = list(unique_cves_set)

    # Obtaining the EPSS scores for the unique CVEs
    epss_scores = get_epss_scores(unique_cves_list)
    
    # Converting the EPSS scores dictionary into a DataFrame
    epss_df = pd.DataFrame.from_dict(epss_scores, orient='index', columns=['EPSS Score'])

    # Saving the DataFrame to a CSV file
    epss_df.to_csv("epss_scores.csv", index_label="CVE")

else:
    print("The column 'CVEs' was not found in the file.")
