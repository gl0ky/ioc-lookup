
import requests
from colorama import Fore, Style, init

init()

class VirusTotalScanner:
    def __init__(self):
        init()

    @staticmethod
    def calculate_reputation_color(reputation):
        if reputation >= 7:
            return Style.BRIGHT + Fore.GREEN  
        elif reputation >= 4:
            return Style.BRIGHT + Fore.YELLOW  
        else:
            return Style.BRIGHT + Fore.RED  
    
    
    @staticmethod
    def scan_ip_with_virustotal(ip_address, api_key):
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
    
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to scan IP {ip_address}. Status code: {response.status_code}")
            return None
    
    @staticmethod
    def write_virustotal_scan_to_txt(json_data, output_file):
        with open(output_file, 'w') as f:
            ip_address = json_data['data']['id']
            ip_type = json_data['data']['type']
            country = json_data['data']['attributes']['country']
            asn = json_data['data']['attributes']['asn']
            regional_internet_registry = json_data['data']['attributes']['regional_internet_registry']
            organization = json_data['data']['attributes']['as_owner']
            f.write(f'IP Address: {ip_address}\n')
            f.write(f'Type: {ip_type}\n')
            f.write(f'Country: {country}\n')
            f.write(f'ASN: {asn}\n')
            f.write(f'Regional Internet Registry: {regional_internet_registry}\n')
            f.write(f'Organization: {organization}\n')
            f.write('\nLast Analysis Stats:\n')
            for key, value in json_data['data']['attributes']['last_analysis_stats'].items():
                f.write(f'    {key.capitalize()}: {value}\n')
            f.write('\nLast Analysis Results:\n')
            for engine, result_data in json_data['data']['attributes']['last_analysis_results'].items():
                f.write(f'    {engine}: {result_data["result"]} ({result_data["category"]})\n')
            f.write('\nTags: None\n')
            f.write(f'Continent: {json_data["data"]["attributes"]["continent"]}\n')
            f.write(f'Network: {json_data["data"]["attributes"]["network"]}\n')
            f.write(f'JARM: {json_data["data"]["attributes"]["jarm"]}\n')
            f.write(f'Whois Date: {json_data["data"]["attributes"]["whois_date"]}\n')
            f.write(f'Whois:\n{json_data["data"]["attributes"]["whois"]}\n')
        
    
    @staticmethod
    def print_ip_info(ip, json_data):
        print("=" * (len(ip) + 16))
        print(f"{Style.BRIGHT}VirusTotal IP Scan".ljust(len(ip) + 16), Style.RESET_ALL)
        print("-" * (len(ip) + 16))
        print(f"{Style.BRIGHT}Dirección IP: {ip}".ljust(len(ip) + 16), Style.RESET_ALL)
        print("-" * (len(ip) + 16))
        print(f"{Style.BRIGHT}País:".ljust(16), json_data['data']['attributes']['country'], Style.RESET_ALL)

        last_analysis_results = json_data['data']['attributes']['last_analysis_results']
        detection_count = sum(1 for result in last_analysis_results.values() if result['result'] != 'unrated')
        total_analysis = len(last_analysis_results)

        reputation = (total_analysis - detection_count) / total_analysis * 10
        reputation_str = f'{reputation:.1f}/10.0'

        print(f"{Style.BRIGHT}Detecciones:".ljust(16), detection_count, "de", total_analysis, Style.RESET_ALL)
        print(f"{Style.BRIGHT}Reputación:".ljust(16), VirusTotalScanner.calculate_reputation_color(reputation) + reputation_str, Style.RESET_ALL)
        print("=" * (len(ip) + 16))

    