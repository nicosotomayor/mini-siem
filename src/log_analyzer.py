#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import time
import json
import yaml
import requests
import pandas as pd
import pyfiglet
import os
from colorama import Fore, init
from collections import defaultdict

# Inicializar colorama
init(autoreset=True)

CONFIG_FILE = "config.yaml"

# ===============================
# Banner ASCII
# ===============================
def show_banner():
    banner = pyfiglet.figlet_format("Mini-SIEM")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "🔎 Log Analyzer - Blue Team Edition")
    print(Fore.RED + "⚠️  Use responsibly. Educational purposes only.")
    print("-" * 70)

# ===============================
# Configuración
# ===============================
def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {"failed_login_threshold": 5, "error_404_threshold": 20}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        yaml.safe_dump(config, f)

# ===============================
# GeoIP Lookup
# ===============================
def geoip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,org,query"
        r = requests.get(url, timeout=5).json()
        if r["status"] == "success":
            return f"{r['country']}, {r['city']} ({r['org']})"
    except:
        return "Desconocido"
    return "Desconocido"

# ===============================
# Procesar logs
# ===============================
def analyze_log(logfile, live=False):
    failed_logins = defaultdict(int)
    error_404 = defaultdict(int)

    config = load_config()
    fl_threshold = config.get("failed_login_threshold", 5)
    err_threshold = config.get("error_404_threshold", 20)

    def process_line(line):
        if "Failed password" in line:
            ip = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                failed_logins[ip[0]] += 1
        if " 404 " in line:
            ip = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                error_404[ip[0]] += 1

    if live:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    process_line(line)
                    show_results(failed_logins, error_404, fl_threshold, err_threshold, logfile)
                time.sleep(1)
    else:
        try:
            with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    process_line(line)
        except FileNotFoundError:
            print(Fore.RED + f"❌ No se encontró el archivo: {logfile}")
            return
        show_results(failed_logins, error_404, fl_threshold, err_threshold, logfile, export=True)

# ===============================
# Mostrar resultados
# ===============================
def show_results(failed_logins, error_404, fl_threshold, err_threshold, logfile, export=False):
    print("\n📊 " + Fore.CYAN + f"Análisis del log: {logfile}\n")

    incidents = {"failed_logins": {}, "error_404": {}, "summary": {}}
    csv_data = []
    severity_score = 0

    if failed_logins:
        for ip, count in failed_logins.items():
            location = geoip_lookup(ip)
            if count >= fl_threshold:
                print(Fore.RED + f"🚨 Fuerza bruta detectada desde {ip} ({count} intentos) 🌍 {location}")
                incidents["failed_logins"][ip] = {"intentos": count, "ubicacion": location}
                severity_score += 40
            else:
                print(Fore.YELLOW + f"⚠️  Intentos fallidos desde {ip}: {count} 🌍 {location}")
            csv_data.append({"tipo": "Failed Login", "ip": ip, "intentos": count, "ubicacion": location})
    else:
        print(Fore.GREEN + "✅ No se detectaron intentos de fuerza bruta.")

    if error_404:
        for ip, count in error_404.items():
            location = geoip_lookup(ip)
            if count >= err_threshold:
                print(Fore.RED + f"🚨 Escaneo web sospechoso desde {ip} ({count} errores 404) 🌍 {location}")
                incidents["error_404"][ip] = {"errores": count, "ubicacion": location}
                severity_score += 30
            else:
                print(Fore.YELLOW + f"⚠️  Errores 404 desde {ip}: {count} 🌍 {location}")
            csv_data.append({"tipo": "404 Error", "ip": ip, "intentos": count, "ubicacion": location})
    else:
        print(Fore.GREEN + "✅ No se detectaron escaneos web.")

    print("\n----------------------------------------------------------------------")
    print("📈 " + Fore.CYAN + "Resumen")
    print(f"   - IPs con intentos fallidos: {len(failed_logins)}")
    print(f"   - IPs con errores 404: {len(error_404)}")
    print(f"   - Severidad total: {severity_score}/100")

    incidents["summary"] = {
        "failed_login_ips": len(failed_logins),
        "error_404_ips": len(error_404),
        "severity": severity_score
    }

    if export:
        with open("report.json", "w") as f:
            json.dump(incidents, f, indent=4)
        with open("report.txt", "w") as f:
            f.write(json.dumps(incidents, indent=4))
        df = pd.DataFrame(csv_data)
        df.to_csv("report.csv", index=False)
        print(Fore.YELLOW + "\n📤 Reportes guardados en: report.json, report.txt y report.csv")

# ===============================
# Menú principal
# ===============================
def main_menu():
    while True:
        show_banner()
        print("[1] Analizar un log estático")
        print("[2] Analizar en tiempo real (live)")
        print("[3] Ver configuración actual")
        print("[4] Cambiar configuración (umbrales)")
        print("[5] Ver historial de reportes")
        print("[6] Salir")
        opcion = input("\n👉 Selecciona una opción: ")

        if opcion == "1":
            logfile = input("Ruta del archivo de log: ")
            analyze_log(logfile, live=False)
            input("\nPresiona ENTER para volver al menú...")
        elif opcion == "2":
            logfile = input("Ruta del archivo de log: ")
            analyze_log(logfile, live=True)
        elif opcion == "3":
            config = load_config()
            print("\n⚙️ Configuración actual:")
            print(json.dumps(config, indent=4))
            input("\nPresiona ENTER para volver al menú...")
        elif opcion == "4":
            config = load_config()
            print("\nConfig actual:", config)
            new_fl = input("Nuevo umbral de intentos fallidos (enter para mantener): ")
            new_err = input("Nuevo umbral de errores 404 (enter para mantener): ")
            if new_fl:
                config["failed_login_threshold"] = int(new_fl)
            if new_err:
                config["error_404_threshold"] = int(new_err)
            save_config(config)
            print(Fore.GREEN + "✅ Configuración actualizada.")
            input("\nPresiona ENTER para volver al menú...")
        elif opcion == "5":
            print("\n📂 Archivos de reportes en carpeta actual:")
            for file in os.listdir("."):
                if file.startswith("report.") and (file.endswith(".json") or file.endswith(".txt") or file.endswith(".csv")):
                    print("   -", file)
            input("\nPresiona ENTER para volver al menú...")
        elif opcion == "6":
            print(Fore.CYAN + "👋 Saliendo de Mini-SIEM...")
            sys.exit(0)
        else:
            print(Fore.RED + "❌ Opción no válida")
            time.sleep(1)

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    main_menu()
