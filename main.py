import argparse
from datetime import datetime

# Importar la clase VirusTotalScanner desde el módulo
from virustotal import VirusTotalScanner


def parse_args():
	parser = argparse.ArgumentParser(description="VirusTotal IP Scanner CLI")

	# Argumento para especificar las direcciones IP
	parser.add_argument('--ip-address', '-ip', type=str, required=True,
						help="Direcciones IP separadas por comas o nombre de archivo con direcciones IP en cada línea")

	# Argumento para especificar la clave de la API de VirusTotal
	parser.add_argument('--virustotal-api-key', type=str,
						help="Clave de la API de VirusTotal")

	# Argumento para activar la escritura en archivo
	parser.add_argument('-oT', action='store_true',
						help="Activar la escritura de resultados en archivo")

	# Argumento para especificar el nombre del archivo de salida
	parser.add_argument('--output-file', type=str,
						help="Nombre del archivo de salida (opcional)")

	parser.add_argument('--virustotal-ip-scan', '-VPS', action='store_true',
						help="Realizar escaneo de VirusTotal para las direcciones IP")

	return parser.parse_args()

def virustotal_ip_scan(args):

	args = parse_args()

	if args.ip_address.endswith('.txt'):
		with open(args.ip_address, 'r') as file:
			ip_addresses = file.readlines()
	else:
		# Obtener las direcciones IP
		ip_addresses = args.ip_address.split(',')

	# Obtener la clave de la API de VirusTotal
	if args.virustotal_api_key:
		api_key = args.virustotal_api_key
	else:
		# Leer la clave de la API de VirusTotal desde un archivo de configuración
		with open('config.cfg') as config_file:
			for line in config_file:
				if line.startswith('virustotal_api_key'):
					api_key = line.split(':')[1].strip()
					break
			else:
				print("No se pudo encontrar la clave de la API de VirusTotal en el archivo de configuración.")
				return

	# Crear una instancia del escáner de VirusTotal
	scanner = VirusTotalScanner()

	# Escanear cada dirección IP
	for ip_address in ip_addresses:
		# Realizar el escaneo de la dirección IP con VirusTotal
		scan_result = scanner.scan_ip_with_virustotal(ip_address.strip(), api_key)

		if scan_result:
			# Imprimir la información de la dirección IP
			scanner.print_ip_info(ip_address.strip(), scan_result)

			# Escribir los resultados en un archivo si se especifica el argumento -oT
			if args.oT:
				output_file = args.output_file
				if not output_file:
					# Generar un nombre de archivo predeterminado basado en la fecha y la IP
					timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
					output_file = f"VirusTotal_ip_scan_results_{ip_address}_{timestamp}.txt"
				# Escribir los resultados en el archivo
				scanner.write_virustotal_scan_to_txt(scan_result, output_file)
		else:
			print(f"No se pudieron obtener los resultados del escaneo para la dirección IP: {ip_address}")


def main():

	args = parse_args()

	# Verificar qué modo de escaneo se ha seleccionado
	if args.virustotal_ip_scan:
		virustotal_ip_scan(args)
	else:
		print("Por favor, seleccione un modo de escaneo válido.")

if __name__ == "__main__":
	main()
