"""One-shot demo reset.

The oscilloscope is captured LIVE from the real ESP32 during the demo, so
this script doesn't touch it at all — just clears the slate so live capture
starts clean.

For the two simulated protocols:
- PSU (mimic_psu_traffic.py): pre-seeded as a "fully deciphered" showcase —
  labels, deciphered fields, and a monitor are all pre-populated, so you can
  jump straight to showing the generated driver function without re-walking
  the (simple, fast) discovery process live.
- Battery tester (mimic_battery_tester_traffic.py): left completely
  unlabeled, for live discovery during the demo — this is the interesting
  one, since the puzzle isn't a byte range at all (there's no resistance
  field on the wire), it's correlating a voltage-under-load reading against
  whatever current you just commanded.

Run this right before presenting. It overwrites capture_log.jsonl and the
label/deciphered/monitor files, then appends the PSU + battery-tester
records. Once you start the live oscilloscope capture during the demo, its
messages will simply append after these at whatever the next index is.
"""

import json
import os

import mimic_battery_tester_traffic as battery
import mimic_psu_traffic as psu

CAPTURE_FILE = "capture_log.jsonl"
LABELS_FILE = "labels.json"
DECIPHERED_FILE = "deciphered.json"
MONITORS_FILE = "monitors.json"


def main():
    for path in (CAPTURE_FILE, LABELS_FILE, DECIPHERED_FILE, MONITORS_FILE):
        if os.path.exists(path):
            os.remove(path)

    psu.main()

    # Record layout from mimic_psu_traffic.main(): one-time set_ocp, one-time
    # set_ovp, then (set_voltage OUT, reading IN) pairs per swept voltage.
    labels = {
        "0": {"name": "set_ocp", "note": "one-time OCP limit", "value": psu.OCP_LIMIT},
        "1": {"name": "set_ovp", "note": "one-time OVP limit", "value": psu.OVP_LIMIT},
    }
    readings = []
    for i, voltage in enumerate(psu.VOLTAGES):
        out_index = 2 + 2 * i
        in_index = out_index + 1
        actual_voltage, actual_current = psu.simulate_reading(voltage, psu.OCP_LIMIT, psu.OVP_LIMIT)
        readings.append((actual_voltage, actual_current))
        labels[str(out_index)] = {"name": "set_voltage", "note": "commanded output voltage", "value": voltage}
        labels[str(in_index)] = {"name": "reading", "note": "actual voltage + current under load", "value": actual_voltage}
    with open(LABELS_FILE, "w") as f:
        json.dump(labels, f, indent=2)

    deciphered = {
        "set_ocp::OUT::limit": {
            "label": "set_ocp", "direction": "OUT", "param": "limit",
            "start": 2, "end": 3, "byte_order": "big", "scale": psu.SCALE,
        },
        "set_ovp::OUT::limit": {
            "label": "set_ovp", "direction": "OUT", "param": "limit",
            "start": 2, "end": 3, "byte_order": "big", "scale": psu.SCALE,
        },
        "set_voltage::OUT::voltage": {
            "label": "set_voltage", "direction": "OUT", "param": "voltage",
            "start": 2, "end": 3, "byte_order": "big", "scale": psu.SCALE,
        },
        "reading::IN::voltage": {
            "label": "reading", "direction": "IN", "param": "voltage",
            "start": 2, "end": 3, "byte_order": "big", "scale": psu.SCALE,
        },
        "reading::IN::current": {
            "label": "reading", "direction": "IN", "param": "current",
            "start": 4, "end": 5, "byte_order": "big", "scale": psu.SCALE,
        },
    }
    with open(DECIPHERED_FILE, "w") as f:
        json.dump(deciphered, f, indent=2)

    monitors = {
        "reading::IN::voltage": {
            "label": "reading", "direction": "IN", "param": "voltage",
            "start": 2, "end": 3, "byte_order": "big", "scale": psu.SCALE,
            "precision": None, "tolerance": 0.15,
        },
        "reading::IN::current": {
            "label": "reading", "direction": "IN", "param": "current",
            "start": 4, "end": 5, "byte_order": "big", "scale": psu.SCALE,
            "precision": None, "tolerance": 0.15,
        },
    }
    with open(MONITORS_FILE, "w") as f:
        json.dump(monitors, f, indent=2)

    # Battery tester: appended raw, deliberately left unlabeled.
    psu_record_count = 2 + 2 * len(psu.VOLTAGES)
    battery_start = psu_record_count
    battery.main()
    battery_count = 2 + 2 * len(battery.CURRENTS)  # 2 voltage-stream reports + (OUT,IN) pairs per current
    battery_end = battery_start + battery_count - 1

    print()
    print(f"PSU: indices 0-{battery_start - 1}, fully labeled/deciphered/watched.")
    print(f"Battery tester: indices {battery_start}-{battery_end}, completely unlabeled — discover this live.")
    print("Oscilloscope: not seeded — capture it live from the real ESP32 during the demo.")


if __name__ == "__main__":
    main()
