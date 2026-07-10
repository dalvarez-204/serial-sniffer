"""Writes synthetic capture records for a deliberately simple PSU protocol —
much simpler than the oscilloscope's (no length field), so it's fast to demo
the discovery/deciphering process live, and to sanity-check the driver
codegen end to end.

Frame: [0x02 STX] [CMD] [payload] [XOR checksum] [0x03 ETX]. Single-field
commands (set_voltage, set_ocp, set_ovp) carry one 16-bit big-endian value
(6 bytes total); the reading response carries two (voltage, current — 8
bytes total). Scale is 1000 for everything (raw = round(value * 1000)), same
convention as the battery tester — a single byte (0-255) would only give
~0.12V of resolution over a 0-30V range, nowhere near enough to represent a
real reading like 30.185V; 16 bits at this scale gives exact millivolt/
milliamp resolution.

The reading also models real bench-PSU behavior: a PSU holds constant
voltage only while the load's current draw stays under the OCP limit. Past
that, it switches to constant-current mode — current clamps at the limit and
voltage sags below whatever you commanded. That's a real behavior worth
showing, not just another byte to decipher: sweeping voltage without
noticing this means half your "readings" don't actually match your setpoint.

Run this, then load the UI — it appends to whatever's already in
capture_log.jsonl rather than overwriting it.
"""

import json
import time

STX = 0x02
ETX = 0x03
CMD_SET_VOLTAGE = 0x01
CMD_READING = 0x02
CMD_SET_OCP = 0x03
CMD_SET_OVP = 0x04

CAPTURE_FILE = "capture_log.jsonl"

SCALE = 1000  # raw = round(value * SCALE) for every field in this protocol
FAKE_LOAD_OHMS = 12.0  # pretend resistive load, purely for a believable CV/CC transition

VOLTAGES = [5.125, 10.25, 15.5, 18.777, 24.999, 30.185]  # commanded output voltage sweep
OCP_LIMIT = 1.5  # amps — low enough that the higher voltages in the sweep hit it
OVP_LIMIT = 30.0  # volts


def xor_checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result


def to_raw(value: float) -> int:
    return max(0, min(65535, round(value * SCALE)))


def from_raw(raw: int) -> float:
    return raw / SCALE


def build_frame(cmd: int, payload: bytes) -> bytes:
    checksum = xor_checksum(bytes([cmd]) + payload)
    return bytes([STX, cmd]) + payload + bytes([checksum, ETX])


def build_set_command(cmd: int, value: float) -> bytes:
    return build_frame(cmd, to_raw(value).to_bytes(2, "big"))


def build_reading(actual_voltage: float, actual_current: float) -> bytes:
    payload = to_raw(actual_voltage).to_bytes(2, "big") + to_raw(actual_current).to_bytes(2, "big")
    return build_frame(CMD_READING, payload)


def simulate_reading(commanded_voltage: float, ocp_limit: float, ovp_limit: float) -> tuple[float, float]:
    """Same CV/CC logic as psu_firmware.ino: clamp to OVP first, then check
    whether the (fake) load's natural current draw would exceed OCP — if so,
    hold current at the limit and let voltage sag instead of holding voltage
    at the commanded setpoint."""
    target_voltage = min(commanded_voltage, ovp_limit)
    natural_current = target_voltage / FAKE_LOAD_OHMS
    if natural_current > ocp_limit:
        actual_current = ocp_limit
        actual_voltage = actual_current * FAKE_LOAD_OHMS  # constant-current mode: voltage sags
    else:
        actual_current = natural_current
        actual_voltage = target_voltage  # constant-voltage mode
    return actual_voltage, actual_current


def main():
    records = []
    t = time.time()

    frame = build_set_command(CMD_SET_OCP, OCP_LIMIT)
    records.append({"timestamp": t, "direction": "OUT", "data_hex": frame.hex()})
    t += 0.05

    frame = build_set_command(CMD_SET_OVP, OVP_LIMIT)
    records.append({"timestamp": t, "direction": "OUT", "data_hex": frame.hex()})
    t += 0.05

    readings = []
    for voltage in VOLTAGES:
        frame = build_set_command(CMD_SET_VOLTAGE, voltage)
        records.append({"timestamp": t, "direction": "OUT", "data_hex": frame.hex()})
        t += 0.05

        actual_voltage, actual_current = simulate_reading(voltage, OCP_LIMIT, OVP_LIMIT)
        readings.append((actual_voltage, actual_current))
        frame = build_reading(actual_voltage, actual_current)
        records.append({"timestamp": t, "direction": "IN", "data_hex": frame.hex()})
        t += 0.05

    with open(CAPTURE_FILE, "a") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    print(f"Appended {len(records)} synthetic PSU records to {CAPTURE_FILE}")
    print(f"OUT ground truth: set_voltage sweep {VOLTAGES} (volts), byte offset 2-3, scale 1000")
    print(f"OUT ground truth: one-time set_ocp={OCP_LIMIT}A and set_ovp={OVP_LIMIT}V, byte offset 2-3, scale 1000")
    print(f"IN ground truth: reading = (actual_voltage, actual_current), byte offsets 2-3 and 4-5, scale 1000")
    print(f"IN readings: {readings}")
    print(f"CV/CC transition happens above ~{OCP_LIMIT * FAKE_LOAD_OHMS:.1f}V given OCP={OCP_LIMIT}A and the fake {FAKE_LOAD_OHMS}-ohm load")


if __name__ == "__main__":
    main()
