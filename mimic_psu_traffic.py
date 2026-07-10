"""Writes synthetic capture records for a deliberately simple PSU protocol —
much simpler than the oscilloscope's (no length field, one data byte per
frame, single-field messages) so it's fast to demo the discovery/deciphering
process live, and to sanity-check the driver codegen end to end.

Frame: [0x02 STX] [CMD] [VALUE] [XOR checksum] [0x03 ETX] — always 5 bytes.

Run this, then load the UI — it appends to whatever's already in
capture_log.jsonl rather than overwriting it.
"""

import json
import time

STX = 0x02
ETX = 0x03
CMD_SET_VOLTAGE = 0x01
CMD_READ_CURRENT = 0x02

CAPTURE_FILE = "capture_log.jsonl"

VOLTAGES = [5, 10, 15, 20, 25, 30]  # commanded output voltage, 0-30V supply
CURRENTS = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]  # measured current draw, 0-5A range


def xor_checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result


def to_255(value: float, vref: float) -> int:
    return int(round((value * 255) / vref))


def build_frame(cmd: int, value_byte: int) -> bytes:
    payload = bytes([cmd, value_byte])
    checksum = xor_checksum(payload)
    return bytes([STX]) + payload + bytes([checksum, ETX])


def main():
    records = []
    t = time.time()

    # OUT: ground truth — value byte at overall frame offset 2, scale 255/30.
    for voltage in VOLTAGES:
        frame = build_frame(CMD_SET_VOLTAGE, to_255(voltage, 30.0))
        records.append({"timestamp": t, "direction": "OUT", "data_hex": frame.hex()})
        t += 0.05

    # IN: ground truth — value byte at overall frame offset 2, scale 255/5.
    for current in CURRENTS:
        frame = build_frame(CMD_READ_CURRENT, to_255(current, 5.0))
        records.append({"timestamp": t, "direction": "IN", "data_hex": frame.hex()})
        t += 0.05

    with open(CAPTURE_FILE, "a") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    print(f"Appended {len(records)} synthetic PSU records to {CAPTURE_FILE}")
    print(f"OUT ground truth: set_voltage sweep {VOLTAGES} (volts), byte offset 2, scale 255/30")
    print(f"IN ground truth: read_current sweep {CURRENTS} (amps), byte offset 2, scale 255/5")


if __name__ == "__main__":
    main()
