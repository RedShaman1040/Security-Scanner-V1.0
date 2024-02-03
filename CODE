import requests
import nmap
import os

# Configuración de la API de VirusTotal
VIRUSTOTAL_API_KEY = 'tu_clave_de_api_de_virustotal'
VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

def scan_file_with_virustotal(file_path):
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (os.path.basename(file_path), file)}
            params = {'apikey': VIRUSTOTAL_API_KEY}
            
            response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, params=params)
            result = response.json()
            
            if result['response_code'] == 1:
                print(f"Resultado de análisis en VirusTotal para {os.path.basename(file_path)}:")
                for scan, details in result['scans'].items():
                    print(f"{scan}: {details['result']}")
            else:
                print(f"No se pudo obtener el resultado de VirusTotal para {os.path.basename(file_path)}")
    except FileNotFoundError:
        print(f"No se encontró el archivo: {file_path}")

def vulnerability_scan(target_ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(target_ip, arguments='-sS -Pn -T4')
        
        print(f"Resultado de escaneo de vulnerabilidades para {target_ip}:")
        for host in nm.all_hosts():
            print(f"Host: {host}")
            for proto in nm[host].all_protocols():
                print(f"Protocolo: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Puerto: {port} - Estado: {nm[host][proto][port]['state']}")
    except nmap.nmap.PortScannerError:
        print(f"No se pudo realizar el escaneo de vulnerabilidades para {target_ip}")

if __name__ == '__main__':
    malware_file_path = input("Ingrese la ruta completa del archivo malicioso: ")
    target_ip = input("Ingrese la dirección IP del objetivo: ")

    scan_file_with_virustotal(malware_file_path)
    vulnerability_scan(target_ip)
