import requests
import json
import csv

# Función para cargar la configuración desde un archivo .json
def cargar_configuracion(ruta_config):
    with open(ruta_config, 'r', encoding='utf-8') as f:
        return json.load(f)

# Cargar configuración desde el archivo config.json
config = cargar_configuracion('config.json')

# Tu API key de VirusTotal
API_KEY = config['api_key']

# Función para leer las IPs desde un archivo .txt y limpiar espacios o saltos de línea
def leer_ips(archivo):
    with open(archivo, 'r', encoding='utf-8') as f:  # Forzamos la codificación a UTF-8
        return [line.strip() for line in f if line.strip()]  # Remueve espacios y líneas vacías

# Función para consultar VirusTotal por cada IP y extraer los datos relevantes
def consultar_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # Extraer el campo "country" y "malicious"
            country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")
            malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            
            # Retornar solo country y malicious
            result = {
                "country": country,
                "malicious": malicious
            }
            
            return result
        else:
            return {"error": f"Error {response.status_code} al consultar la IP {ip}"}
    except Exception as e:
        return {"error": f"Excepción al consultar la IP {ip}: {str(e)}"}

# Función para iterar sobre las IPs y validarlas
def validar_ips(lista_ips):
    resultados = []
    errores = []
    
    for ip in lista_ips:
        resultado = consultar_ip_virustotal(ip)
        if "error" not in resultado:
            resultados.append({
                "IP": ip,
                "country": resultado["country"],
                "malicious": resultado["malicious"]
            })
        else:
            errores.append({
                "IP": ip,
                "error": resultado['error']
            })
            print(f"Error con la IP {ip}: {resultado['error']}")
    
    return resultados, errores

# Función para guardar los resultados en un archivo CSV con delimitador ;
def guardar_resultados_csv(resultados, archivo_salida):
    with open(archivo_salida, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['IP', 'country', 'malicious']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')  # Usar ; como delimitador
        
        writer.writeheader()  # Escribir los encabezados
        writer.writerows(resultados)  # Escribir los datos de cada IP

# Función para guardar los errores en un archivo CSV
def guardar_errores_csv(errores, archivo_salida):
    with open(archivo_salida, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['IP', 'error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')  # Usar ; como delimitador
        
        writer.writeheader()  # Escribir los encabezados
        writer.writerows(errores)  # Escribir los datos de errores

# Main - flujo principal
if __name__ == "__main__":
    # Especifica el archivo de IPs desde la configuración
    archivo_ips = config['archivo_ips']
    
    # Leer las IPs del archivo
    lista_ips = leer_ips(archivo_ips)
    
    # Validar las IPs con VirusTotal
    resultados, errores = validar_ips(lista_ips)
    
    # Guardar los resultados en un archivo CSV
    guardar_resultados_csv(resultados, config['archivo_resultados'])
    
    # Guardar los errores en un archivo CSV
    guardar_errores_csv(errores, config['archivo_errores'])
    
    # Mostrar los resultados en consola (opcional)
    for resultado in resultados:
        print(f"IP: {resultado['IP']}, Country: {resultado['country']}, Malicious: {resultado['malicious']}")
    
    # Mostrar los errores en consola (opcional)
    for error in errores:
        print(f"IP: {error['IP']} - Error: {error['error']}")
