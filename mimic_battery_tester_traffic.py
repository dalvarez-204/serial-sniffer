"""Writes synthetic capture records for a battery/impedance-tester protocol,
based on real host-side control code (batt_tester_interpreter.txt.txt) —
NOT the device's firmware, which was never available, so this isn't a
bit-exact replica. What's confirmed straight from that script (verified by
reproducing its checksum arithmetic against every real sample frame in it):

    Frame: [0xFA START] [CMD] [6 payload bytes] [XOR checksum of CMD+payload]
           [0xF8 END] — 10 bytes total.
    CMD 0x05 = init, CMD 0x06 = close (both zero payload).
    CMD 0x09 = "run a test at this current" (payload bytes 0-1, big-endian) —
        the real script's own current->raw-value mapping isn't linear
        (1..5A encode to 100/200/316/416/532), so whatever scale the real
        firmware actually uses couldn't be recovered from the host script
        alone. This mimic uses a clean, made-up linear scale instead.

THE ACTUAL CHALLENGE (per the human who wrote the real script — this is the
important part, and the thing an earlier version of this mimic got wrong by
inventing a "resistance" field that never existed on the wire):

    The device never transmits resistance. It only ever reports voltage —
    once as a periodic/unprompted open-circuit reading (confirmed scale
    1000 straight from the real get_voltage()), and once as a voltage-under-
    load reading sent specifically in response to a run-test command. The
    host script derives resistance itself: R = (open-circuit V - loaded V) /
    commanded current — Ohm's law, computed after the fact by correlating an
    IN reading against whatever OUT command preceded it. There's no field
    called "resistance" to find by deciphering a single message; you have to
    notice the loaded-voltage reading depends on the current you just sent
    and do the division yourself, same as the real host software does.

Run this, then load the UI — it appends to whatever's already in
capture_log.jsonl rather than overwriting it.
"""

import json
import time

START = 0xFA
END = 0xF8
CMD_RUN_TEST = 0x09
CMD_VOLTAGE_STREAM = 0x0B  # invented — periodic open-circuit voltage report
CMD_TEST_RESPONSE = 0x0A  # invented — reply to CMD_RUN_TEST, voltage under load

CAPTURE_FILE = "capture_log.jsonl"

OPEN_CIRCUIT_VOLTAGE = 3.90  # volts, resting voltage of a healthy 21700 cell
ASSUMED_RESISTANCE_OHMS = 0.025  # 25 mOhm — the "ground truth" this mimic bakes in
CURRENTS = [1, 2, 3, 4, 5]  # amps, swept setpoints (OUT)


def xor_checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result


def build_frame(cmd: int, payload: bytes) -> bytes:
    payload = payload.ljust(6, b"\x00")[:6]
    checksum = xor_checksum(bytes([cmd]) + payload)
    return bytes([START, cmd]) + payload + bytes([checksum, END])


def build_run_test(current_amps: int) -> bytes:
    raw_current = round(current_amps * 100)  # made-up linear scale, see module docstring
    payload = raw_current.to_bytes(2, "big") + b"\x00\x00\x00\x00"
    return build_frame(CMD_RUN_TEST, payload)


def build_voltage_report(cmd: int, voltage: float) -> bytes:
    raw_voltage = round(voltage * 1000)  # confirmed scale, from the real get_voltage()
    payload = raw_voltage.to_bytes(2, "big") + b"\x00\x00\x00\x00"
    return build_frame(cmd, payload)


def main():
    records = []
    t = time.time()

    # a couple of unprompted open-circuit voltage reports before any test
    # runs, mirroring the real script's "read whatever's already waiting"
    # step that happens before it ever sends a test command
    for _ in range(2):
        frame = build_voltage_report(CMD_VOLTAGE_STREAM, OPEN_CIRCUIT_VOLTAGE)
        records.append({"timestamp": t, "direction": "IN", "data_hex": frame.hex()})
        t += 0.05

    loaded_voltages = []
    for current in CURRENTS:
        out_frame = build_run_test(current)
        records.append({"timestamp": t, "direction": "OUT", "data_hex": out_frame.hex()})
        t += 0.05

        loaded_voltage = OPEN_CIRCUIT_VOLTAGE - current * ASSUMED_RESISTANCE_OHMS
        loaded_voltages.append(loaded_voltage)
        in_frame = build_voltage_report(CMD_TEST_RESPONSE, loaded_voltage)
        records.append({"timestamp": t, "direction": "IN", "data_hex": in_frame.hex()})
        t += 0.05

    with open(CAPTURE_FILE, "a") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    print(f"Appended {len(records)} synthetic battery-tester records to {CAPTURE_FILE}")
    print(f"OUT ground truth: current sweep {CURRENTS} (amps), byte offset 2-3, scale 100 (made up, see docstring)")
    print(f"IN ground truth: open-circuit voltage {OPEN_CIRCUIT_VOLTAGE}V (CMD 0x0b), byte offset 2-3, scale 1000 (confirmed)")
    print(f"IN ground truth: voltage under load {loaded_voltages} (CMD 0x0a), byte offset 2-3, scale 1000 (confirmed)")
    print(f"No resistance field exists on the wire — it's (open V - loaded V) / current, computed by the host, "
          f"same as the real script. Ground truth resistance here is {ASSUMED_RESISTANCE_OHMS * 1000:.0f} mOhm.")


if __name__ == "__main__":
    main()
