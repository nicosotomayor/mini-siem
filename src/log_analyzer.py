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
import datetime
import matplotlib.pyplot as plt
from colorama import Fore, init
from collections import defaultdict, Counter

# Inicializar colorama
init(autoreset=True)

CONFIG_FILE = "config.yaml"
REPORTS_DIR = "reports"

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
# Crear carpeta reports si no existe
# ===============================
def ensure_reports_dir():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

# ===============================
# Analizar log
# ===============================
def analyze_log(logfile, live=False):
    failed_logins = defaultdict(int)
    error_404 = defaultdict(int)
    successful_root = defaultdict(int)
    all_ips = []

    config = load_config()
    fl_threshold = config.get("failed_login_threshold", 5)
    err_threshold = config.get("error_404_threshold", 20)

    def process_line(line):
        # Fuerza bruta
        if "Failed password" in line:
            ip = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                failed_logins[ip[0]] += 1
                all_ips.append(ip[0])
        # Root login exitoso
        if "Accepted password for root" in line:
            ip = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                successful_root[ip[0]] += 1
                all_ips.append(ip[0])
        # Error 404
        if " 404 " in line:
            ip = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                error_404[ip[0]] += 1
                all_ips.append(ip[0])

    if live:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    process_line(line)
                    show_results(failed_logins, error_404, successful_root, all_ips, fl_threshold, err_threshold, logfile)
                time.sleep(1)
    else:
        try:
            with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    process_line(line)
        except FileNotFoundError:
            print(Fore.RED + f"❌ No se encontró el archivo: {logfile}")
            return
        show_results(failed_logins, error_404, successful_root, all_ips, fl_threshold, err_threshold, logfile, export=True)

# ===============================
# Mostrar resultados
# ===============================
def show_results(failed_logins, error_404, successful_root, all_ips, fl_threshold, err_threshold, logfile, export=False):
    print("\n📊 " + Fore.CYAN + f"Análisis del log: {logfile}\n")

    incidents = {"failed_logins": {}, "error_404": {}, "root_logins": {}, "summary": {}}
    csv_data = []
    severity_score = 0
    suspicious = False  # bandera de actividad sospechosa

    # Fuerza bruta
    for ip, count in failed_logins.items():
        suspicious = True
        location = geoip_lookup(ip)
        if count >= fl_threshold:
            print(Fore.RED + f"🚨 Fuerza bruta desde {ip} ({count} intentos) 🌍 {location}")
            incidents["failed_logins"][ip] = {"intentos": count, "ubicacion": location}
            severity_score += 40
        else:
            print(Fore.YELLOW + f"⚠️ Intentos fallidos desde {ip}: {count} 🌍 {location}")
        csv_data.append({"tipo": "Failed Login", "ip": ip, "intentos": count, "ubicacion": location})

    # Root logins
    for ip, count in successful_root.items():
        suspicious = True
        location = geoip_lookup(ip)
        print(Fore.RED + f"🚨 Login ROOT exitoso desde {ip} ({count} veces) 🌍 {location}")
        incidents["root_logins"][ip] = {"exitosos": count, "ubicacion": location}
        severity_score += 50
        csv_data.append({"tipo": "Root Login", "ip": ip, "intentos": count, "ubicacion": location})

    # Escaneo web
    for ip, count in error_404.items():
        suspicious = True
        location = geoip_lookup(ip)
        if count >= err_threshold:
            print(Fore.RED + f"🚨 Escaneo web sospechoso {ip} ({count} errores 404) 🌍 {location}")
            incidents["error_404"][ip] = {"errores": count, "ubicacion": location}
            severity_score += 30
        else:
            print(Fore.YELLOW + f"⚠️ Errores 404 desde {ip}: {count} 🌍 {location}")
        csv_data.append({"tipo": "404 Error", "ip": ip, "intentos": count, "ubicacion": location})

    # Si no hubo nada sospechoso
    if not suspicious:
        print(Fore.GREEN + "✅ No se detectó actividad sospechosa.")
        print(Fore.CYAN + "↩️ Volviendo al menú principal...\n")
        return

    # Top IPs
    if all_ips:
        top_ips = Counter(all_ips).most_common(5)
        print("\n🏆 Top 5 IPs más activas:")
        for ip, cnt in top_ips:
            print(f"   - {ip} ({cnt} eventos)")
        incidents["summary"]["top_ips"] = dict(top_ips)

    # Resumen
    print("\n----------------------------------------------------------------------")
    print("📈 " + Fore.CYAN + "Resumen")
    print(f"   - IPs con intentos fallidos: {len(failed_logins)}")
    print(f"   - IPs con errores 404: {len(error_404)}")
    print(f"   - Logins root: {len(successful_root)}")
    print(f"   - Severidad total: {severity_score}/100")

    # Exportar reportes
    if export:
        ensure_reports_dir()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        base = os.path.join(REPORTS_DIR, f"{timestamp}-report")

        with open(base + ".json", "w") as f:
            json.dump(incidents, f, indent=4)
        with open(base + ".txt", "w") as f:
            f.write(json.dumps(incidents, indent=4))
        df = pd.DataFrame(csv_data)
        df.to_csv(base + ".csv", index=False)
        print(Fore.YELLOW + f"\n📤 Reportes guardados en {REPORTS_DIR}/ con timestamp {timestamp}")

# ===============================
# Generar log demo
# ===============================
def generate_demo_log():
    demo = """Failed password for root from 192.168.1.10 port 22 ssh2
Failed password for admin from 185.22.33.44 port 22 ssh2
Accepted password for root from 203.0.113.5 port 22 ssh2
192.168.1.20 - - [30/Mar/2025:10:20:30] "GET /noexiste HTTP/1.1" 404 -
45.12.90.3 - - [30/Mar/2025:10:20:31] "GET /admin HTTP/1.1" 404 -
"""
    with open("test.log", "w") as f:
        f.write(demo)
    return "test.log"

# ===============================
# Generar gráfico de IPs
# ===============================
def generate_graph(logfile):
    ips = []
    try:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                found = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
                ips.extend(found)
    except:
        print(Fore.RED + "❌ No se pudo leer el log.")
        return
    if not ips:
        print(Fore.YELLOW + "⚠️ No se encontraron IPs.")
        return
    counter = Counter(ips)
    df = pd.DataFrame(counter.items(), columns=["IP", "Eventos"])
    df = df.sort_values(by="Eventos", ascending=False).head(10)
    df.plot(kind="bar", x="IP", y="Eventos", legend=False, color="red")
    plt.title(f"Top IPs en {logfile}")
    plt.ylabel("Eventos")
    plt.tight_layout()
    plt.show()

# ===============================
# Menú principal
# ===============================
def main_menu():
    while True:
        show_banner()
        print("[1] Analizar log estático")
        print("[2] Analizar en tiempo real (live)")
        print("[3] Ver configuración actual")
        print("[4] Cambiar configuración")
        print("[5] Ver historial de reportes")
        print("[6] Generar gráfico de IPs")
        print("[7] Modo demo (log simulado)")
        print("[8] Salir")
        opcion = input("\n👉 Selecciona una opción: ")

        if opcion == "1":
            print("\n[1] /var/log/auth.log")
            print("[2] /var/log/apache2/access.log")
            print("[3] /var/log/syslog")
            print("[4] Ingresar ruta manual")
            sub = input("\nSelecciona log: ")
            if sub == "1":
                logfile = "/var/log/auth.log"
            elif sub == "2":
                logfile = "/var/log/apache2/access.log"
            elif sub == "3":
                logfile = "/var/log/syslog"
            elif sub == "4":
                logfile = input("Ruta del archivo: ")
            else:
                print("❌ Opción inválida.")
                continue
            analyze_log(logfile, live=False)
            input("\nPresiona ENTER para volver al menú...")

        elif opcion == "2":
            logfile = input("Ruta del archivo de log: ")
            analyze_log(logfile, live=True)

        elif opcion == "3":
            config = load_config()
            print("\n⚙️ Config actual:")
            print(json.dumps(config, indent=4))
            input("\nPresiona ENTER para volver al menú...")

        elif opcion == "4":
            config = load_config()
            new_fl = input("Umbral de intentos fallidos (enter = mantener): ")
            new_err = input("Umbral de errores 404 (enter = mantener): ")
            if new_fl:
                config["failed_login_threshold"] = int(new_fl)
            if new_err:
                config["error_404_threshold"] = int(new_err)
            save_config(config)
            print(Fore.GREEN + "✅ Configuración actualizada.")
            input("\nPresiona ENTER para volver al menú...")

        elif opcion == "5":
            print("\n📂 Reportes disponibles en carpeta reports/:")
            ensure_reports_dir()
            for file in os.listdir(REPORTS_DIR):
                print("   -", file)
            input("\nPresiona ENTER para volver al menú...")

        elif opcion == "6":
            logfile = input("Ruta del log para graficar: ")
            generate_graph(logfile)
            input("\nPresiona ENTER para volver al menú...")

        elif opcion == "7":
            logfile = generate_demo_log()
            print(f"\n⚡ Log demo generado: {logfile}")
            analyze_log(logfile, live=False)
            input("\nPresiona ENTER para volver al menú...")

        elif opcion == "8":
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

