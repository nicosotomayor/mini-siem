# 🛡️ Mini-SIEM - Log Analyzer  

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/) 
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  

Herramienta en **Python** que analiza logs del sistema para detectar patrones sospechosos, como:  
- 🚨 **Ataques de fuerza bruta** (múltiples intentos fallidos de login).  
- 🔎 **Escaneos web** (muchos errores 404 en poco tiempo).  

Ideal para practicar habilidades de **Blue Team / SOC** en entornos Linux.  

---

## 🚀 Instalación y dependencias

```bash
# Clonar el repositorio
git clone https://github.com/nicosotomayor/mini-siem.git
cd mini-siem

# Instalar dependencias
sudo apt update
sudo apt install python3-pip -y
pip install -r requirements.txt
▶️ Uso
bash
Copiar código
# Analizar un log estático (ejemplo auth.log)
python3 src/log_analyzer.py /var/log/auth.log

# Analizar en tiempo real (modo live)
python3 src/log_analyzer.py /var/log/auth.log --live
📋 Ejemplo de salida
text
Copiar código
 __  __ _       _ ____   _____ ___  
|  \/  (_)_ __ (_) ___| |_   _/ _ \ 
| |\/| | | '_ \| \___ \   | || | | |
| |  | | | | | | |___) |  | || |_| |
|_|  |_|_|_| |_|_|____/   |_| \___/  

🔎 Log Analyzer - Blue Team Edition
⚠️  Use responsibly. Educational purposes only.
----------------------------------------------------------------------

📊 Análisis del log: /var/log/auth.log

🚨 Fuerza bruta detectada desde 185.22.33.44 (27 intentos fallidos)
⚠️  Errores 404 desde 45.12.90.3: 18
✅ No se detectaron escaneos web.

----------------------------------------------------------------------  
📈 Resumen
   - IPs con intentos fallidos: 3
   - IPs con errores 404: 1
   - Severidad total: 70/100

📤 Reportes guardados en: report.json y report.txt
📂 Archivos principales
src/log_analyzer.py → Código principal.

config.yaml → Configuración de umbrales (ej: intentos fallidos = 5, errores 404 = 20).

requirements.txt → Dependencias (colorama, pyfiglet, pyyaml).

report.json → Reporte exportado en JSON.

report.txt → Reporte exportado en TXT.

📜 Licencia
Este proyecto está bajo la licencia MIT.
Consulta el archivo LICENSE para más detalles.