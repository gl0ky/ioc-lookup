# IoC Lookup

Este script de Python utiliza la API de VirusTotal para escanear direcciones IP y obtener información sobre su reputación.

## Instalación

Asegúrate de tener Python instalado en tu sistema. Luego, sigue estos pasos para instalar las dependencias y ejecutar el script:

1. Clona este repositorio:

  ```bash
   git clone https://github.com/tu_usuario/ioc-lookup.git
   ```
2. Installa las dependencias:
 ```bash
   pip install -r requirements.txt
   ```
## Uso

Para utilizar el script, ejecútalo desde la línea de comandos proporcionando una dirección IP:

```bash
python3 ioclookup.py -ip <dirección_ip>
```
También puedes especificar un archivo de salida CSV opcional utilizando la opción -o:
```bash
python3 ioclookup.py -ip <dirección_ip> -o <archivo_salida.csv>
```

### Opciones 
- -ip: Especifica la dirección IP que deseas escanear.
- -o: (Opcional) Nombre del archivo de salida en formato CSV.
