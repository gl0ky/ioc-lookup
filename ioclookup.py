import argparse
import csv
from datetime import datetime
from colorama import init, Fore, Style
import requests

# Inicializar colorama
init()

def calculate_reputation_color(reputation):
	"""
	Calcula el color a utilizar para representar la reputación basada en un valor numérico.

	Args:
		reputation (float): Valor de la reputación.

	Returns:
		str: Código de color correspondiente (Fore.RED, Fore.YELLOW o Fore.GREEN).
	"""
	if reputation <= 3:
		return Fore.RED
	elif reputation <= 7:
		return Fore.YELLOW
	else:
		return Fore.GREEN

def virusTotalScan(ip, output_file=None):
	"""
	Escanea una dirección IP utilizando la API de VirusTotal y muestra la información en la consola.
	También guarda la información en un archivo CSV si se especifica.

	Args:
		ip (str): Dirección IP a escanear.
		output_file (str, optional): Nombre del archivo de salida en formato CSV. Por defecto es None.
	"""
	api_key = "YOUR-API-KEY" #Virus total API
	url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
	headers = {'x-apikey': api_key}

	response = requests.get(url, headers=headers)

	if response.status_code == 200:
		json_response = response.json()
		data = json_response['data']
		attributes = data['attributes']

		print_ip_info(ip, attributes)  # Mostrar información en la consola

		if output_file:
			write_to_csv(output_file, ip, attributes)  # Guardar información en archivo CSV

	else:
		print(f"No se pudo obtener el análisis de la IP {ip}. Código de estado HTTP: {response.status_code}")

def print_ip_info(ip, attributes):
	"""
	Muestra la información de la IP en la consola.

	Args:
		ip (str): Dirección IP.
		attributes (dict): Atributos de la IP obtenidos de la API de VirusTotal.
	"""
	print("=" * (len(ip) + 16))
	print(f"{Style.BRIGHT}Dirección IP: {ip}".ljust(len(ip) + 16), Style.RESET_ALL)
	print("=" * (len(ip) + 16))
	print(f"{Style.BRIGHT}País:".ljust(16), attributes['country'], Style.RESET_ALL)

	last_analysis_results = attributes['last_analysis_results']
	detection_count = sum(1 for result in last_analysis_results.values() if result['result'] != 'unrated')
	total_analysis = len(last_analysis_results)

	# Calcular el nivel de reputación
	reputation = (total_analysis - detection_count) / total_analysis * 10
	reputation_str = f'{reputation:.1f}/10.0'

	print(f"{Style.BRIGHT}Detecciones:".ljust(16), detection_count, "de", total_analysis, Style.RESET_ALL)
	print(f"{Style.BRIGHT}Reputación:".ljust(16), calculate_reputation_color(reputation) + reputation_str, Style.RESET_ALL)
	print("-" * (len(ip) + 16) + "\n")

def write_to_csv(output_file, ip, attributes):
	"""
	Escribe la información de la IP en un archivo CSV.

	Args:
		output_file (str): Nombre del archivo CSV.
		ip (str): Dirección IP.
		attributes (dict): Atributos de la IP obtenidos de la API de VirusTotal.
	"""
	detection_count = sum(1 for result in attributes['last_analysis_results'].values() if result['result'] != 'unrated')
	total_analysis = len(attributes['last_analysis_results'])
	reputation = (total_analysis - detection_count) / total_analysis * 10
	reputation_str = f'{reputation:.1f}/10.0'

	with open(output_file, 'a', newline='') as csvfile:
		csv_writer = csv.writer(csvfile, delimiter=':')
		csv_writer.writerow([ip, attributes['country'], detection_count, total_analysis, reputation_str])

def main():
	"""
	Función principal que maneja los argumentos de línea de comandos y ejecuta el escaneo de IP.
	"""
	parser = argparse.ArgumentParser(description="Analiza las IPs utilizando VirusTotal API")
	parser.add_argument("-ip", dest="ip_input", help="IP o ruta al archivo que contiene las direcciones IP a analizar")
	parser.add_argument("-o", dest="output_file", nargs='?', const=datetime.now().strftime("scan-results-%Y-%m-%d_%H-%M-%S.csv"), help="Nombre del archivo de salida en formato CSV")
	args = parser.parse_args()

	if args.ip_input:
		if args.ip_input.endswith('.txt'):
			with open(args.ip_input, 'r') as file:
				ip_list = file.readlines()
				for ip in ip_list:
					ip = ip.strip()  # Eliminar espacios en blanco y saltos de línea
					virusTotalScan(ip, args.output_file)
		else:
			virusTotalScan(args.ip_input, args.output_file)
	else:
		print("Por favor, proporciona la IP o la ruta al archivo de lista de IPs utilizando el argumento -ip")

if __name__ == "__main__":
	main()
