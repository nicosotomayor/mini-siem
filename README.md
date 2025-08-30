# 🛡️ Mini-SIEM - Log Analyzer  

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/) 
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  

Herramienta en **Python** que analiza logs del sistema para detectar patrones sospechosos, como:  
- 🚨 **Ataques de fuerza bruta** (múltiples intentos fallidos de login).  
- 🔎 **Escaneos web** (muchos errores 404 en poco tiempo).  

Ideal para practicar habilidades de **Blue Team / SOC** en entornos Linux.  

---

## 🚀 Instalación y dependencias




# Descargar el repositorio
git clone https://github.com/nicosotomayor/mini-siem.git
cd mini-siem

# Instalar dependencias
sudo apt update
sudo apt install python3-colorama python3-pyfiglet python3-yaml python3-requests python3-pandas -y

# Ejecutar la aplicación
python3 src/log_analyzer.py
