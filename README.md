# VirusTotal IP Checker

Este proyecto permite consultar la reputación de varias direcciones IP utilizando la API de VirusTotal. El script toma una lista de IPs desde un archivo `.txt`, las consulta en VirusTotal y luego guarda los resultados en archivos `.csv`.

## Requisitos previos

Antes de comenzar, asegúrate de tener instalado lo siguiente en tu sistema:

- [Python 3.x](https://www.python.org/downloads/)
- Una cuenta en [VirusTotal](https://www.virustotal.com/) para obtener una API Key

## Instalación

1. **Clona el repositorio**:
   ```bash
   git clone https://github.com/DarcanoS/analyze_ips_virus_total.git
   cd analyze_ips_virus_total
   ```

2. **Crea un entorno virtual** (recomendado):
   En el directorio del proyecto, crea y activa un entorno virtual de Python:
   ```bash
   python -m venv env
   ```

   - En Windows:
     ```bash
     env\Scripts\activate
     ```

   - En macOS/Linux:
     ```bash
     source env/bin/activate
     ```

3. **Instala las dependencias**:
   Con el entorno virtual activado, instala las dependencias necesarias desde el archivo `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

## Configuración

1. **Configura el archivo `config.json`**:
   El archivo `config.json.example` contiene un ejemplo de cómo debe estar configurado el archivo `config.json`. Cópialo y edítalo con tu propia API Key de VirusTotal y los nombres de los archivos de entrada y salida.

   ```bash
   cp config.json.example config.json
   ```

   Luego, abre el archivo `config.json` y edita el valor de `api_key` con tu clave personal de VirusTotal:

   ```json
   {
       "api_key": "TU_API_KEY_AQUI",
       "archivo_ips": "test.txt",
       "archivo_resultados": "resultados_virustotal.csv",
       "archivo_errores": "errores_virustotal.csv"
   }
   ```

2. **Prepara el archivo de IPs**:
   Crea un archivo de texto llamado `test.txt` (o cualquier otro nombre configurado en `config.json`) con una lista de IPs, cada una en una nueva línea.

   Ejemplo de contenido de `test.txt`:
   ```
   8.8.8.8
   1.1.1.1
   ```

## Uso

Con el entorno virtual activado y las configuraciones correctas, ejecuta el script principal:

```bash
python prueba.py
```

El script hará lo siguiente:

1. Leerá las IPs del archivo especificado en `config.json`.
2. Consultará la API de VirusTotal por cada IP.
3. Guardará los resultados en un archivo `.csv` con el nombre especificado en `config.json`.
4. Si alguna IP genera un error (por ejemplo, una IP no válida), se registrará en un archivo de errores.

## Estructura del proyecto

```
virustotal-ip-checker/
│
├── config.json.example   # Archivo de ejemplo de configuración (edítalo para crear config.json)
├── main.py               # Script principal del proyecto
├── requirements.txt      # Dependencias del proyecto
├── test.txt              # Archivo de entrada con las IPs (ejemplo)
├── .gitignore            # Archivos ignorados por git
├── README.md             # Documentación del proyecto
└── venv/                 # Entorno virtual (ignorado por git)
```

## Consideraciones

- Asegúrate de no compartir tu archivo `config.json` con tu clave de API en repositorios públicos.
- La API de VirusTotal tiene un límite de consultas por minuto en la versión gratuita, ten esto en cuenta si tienes muchas IPs que consultar.

## Contribuciones

¡Las contribuciones son bienvenidas! Si tienes mejoras o encuentras algún problema, abre un [issue](https://github.com/tu_usuario/virustotal-ip-checker/issues) o envía un pull request.

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.