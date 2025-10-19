#!/usr/bin/env python3
# netscanner_fixed.py

from scapy.all import ARP, Ether, srp, conf
import os
import sys
import re
import platform

# Colores (ANSI; en Windows antiguas consolas puede que no se muestren)
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_ORANGE = "\033[38;5;208m"
RESET_COLOR = "\033[0m"

def is_admin():
    """
    Devuelve True si el proceso tiene privilegios de administrador/root.
    Funciona en Unix y en Windows (usa ctypes).
    """
    try:
        if os.name == "nt":
            import ctypes
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            # Unix-like
            return os.geteuid() == 0
    except AttributeError:
        # Fallback seguro
        return False

def clear_screen():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def print_banner():
    try:
        with open('banner.txt', 'r', encoding='utf-8') as b:
            for line in b:
                print(line.rstrip().replace('#', ''))
    except FileNotFoundError:
        # Banner no esencial; mostrar uno simple
        print("=== NetScanner ===")

def scan_ips(ip_range):
    # Avisa si falta soporte pcap (Scapy ya imprime warning, aquí reforzamos)
    # conf.use_pcap no siempre puede activarse; dejamos la advertencia para el usuario
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    # srp devuelve (answered, unanswered)
    answered = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def is_likely_gateway(ip_str):
    # Consideramos gateway si el último octeto es '1' (heurística común)
    try:
        last = ip_str.strip().split('.')[-1]
        return last == '1'
    except Exception:
        return False

def main():
    # Comprueba privilegios
    if not is_admin():
        if os.name == "nt":
            print(f"\n{COLOR_ORANGE}This script should be run as Administrator (Windows).{RESET_COLOR}")
            print(f"Right-click your terminal and choose 'Run as administrator', then re-run the script.\n")
        else:
            print(f"\nThis script requires administrator privileges ({COLOR_ORANGE}sudo{RESET_COLOR}) to run correctly.")
            print(f"Please {COLOR_GREEN}rerun{RESET_COLOR} the script with {COLOR_ORANGE}sudo{RESET_COLOR}.\n")
        sys.exit(1)

    clear_screen()
    print_banner()

    # IP range pattern (simple)
    ip_range_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$")

    while True:
        try:
            ip_range = input("Insert IP range or private network (Example: 192.168.1.0/24): ").strip()
        except KeyboardInterrupt:
            print("\n\n")
            print(f"   {COLOR_YELLOW}> Ctrl+c pressed. Exiting... <{RESET_COLOR}\n\n")
            sys.exit(0)

        if ip_range_pattern.match(ip_range):
            print("\n")
            print(f"   {COLOR_GREEN}> {ip_range} is a valid IP range! <{RESET_COLOR}\n")
            break
        else:
            print("\n")
            print(f"   {COLOR_RED}> Invalid argument '{ip_range}', please try again! <{RESET_COLOR}\n\n")

    print("\n")
    # Informar si scapy detectó pcap o no (aunque scapy ya muestra un warning)
    if not conf.use_pcap:
        print(f"{COLOR_YELLOW}Warning: Scapy is not using a pcap provider (Npcap/WinPcap).")
        print("On Windows, install Npcap and run the script as Administrator. On Unix, ensure libpcap is available.{RESET_COLOR}\n")

    devices = scan_ips(ip_range)
    print('---------------------------------------------')
    print(f"Active devices on {ip_range} IP range:")
    print('---------------------------------------------')
    if not devices:
        print(f"{COLOR_YELLOW}No devices found (timeout or insufficient privileges).{RESET_COLOR}")
    for device in devices:
        if is_likely_gateway(device['ip']):
            print(f"(*) IP: {device['ip']} - MAC: {device['mac']}  {COLOR_ORANGE}> Gateway <{RESET_COLOR}")
            print('---------------------------------------------')
        else:
            print(f"(*) IP: {device['ip']} - MAC: {device['mac']}  {COLOR_GREEN}> Host <{RESET_COLOR}")
            print('---------------------------------------------')
    print("\n")

if __name__ == "__main__":
    main()
