"""One-shot demo reset.

Regenerates the oscilloscope capture from scratch and pre-fills its labels /
deciphered fields / a monitor so it demos as "fully deciphered" (all four
set_waveform parameters, plus the ADC reading) without any live clicking —
meant to show off the tool's ceiling on a complex protocol.

Then appends a completely fresh, unlabeled PSU capture on top, for live
discovery/deciphering during the demo — the PSU protocol is deliberately
simple (mimic_psu_traffic.py) so that part of the walkthrough is fast.

Run this right before presenting. It overwrites capture_log.jsonl and the
label/deciphered/monitor files.
"""

import json
import os

import mimic_oscilloscope_traffic as oscilloscope
import mimic_psu_traffic as psu

CAPTURE_FILE = "capture_log.jsonl"
LABELS_FILE = "labels.json"
DECIPHERED_FILE = "deciphered.json"
MONITORS_FILE = "monitors.json"


def main():
    for path in (CAPTURE_FILE, LABELS_FILE, DECIPHERED_FILE, MONITORS_FILE):
        if os.path.exists(path):
            os.remove(path)

    oscilloscope.main()

    # One scalar Value per message (matches the current label model — naming
    # which byte range a value corresponds to happens at Mark-deciphered time,
    # not via per-message named parameters). Amplitude is the swept quantity
    # for the OUT messages here, so that's what gets labeled as the Value;
    # wave_type/freq/offset are constant in this capture and were deciphered
    # directly below from ground truth, not discovered via a live sweep search.
    labels = {}
    for i, amplitude in enumerate(oscilloscope.AMPLITUDES):
        labels[str(i)] = {
            "name": "set_waveform",
            "note": "wave-gen command, amplitude sweep",
            "value": amplitude,
        }
    out_count = len(oscilloscope.AMPLITUDES)
    for j, voltage in enumerate(oscilloscope.VOLTAGES):
        labels[str(out_count + j)] = {
            "name": "channel0_reading",
            "note": "ADC channel 0 voltage readback",
            "value": voltage,
        }
    with open(LABELS_FILE, "w") as f:
        json.dump(labels, f, indent=2)

    deciphered = {
        "set_waveform::OUT::wave_type": {
            "label": "set_waveform", "direction": "OUT", "param": "wave_type",
            "start": 4, "end": 4, "byte_order": "big", "scale": 1,
        },
        "set_waveform::OUT::freq": {
            "label": "set_waveform", "direction": "OUT", "param": "freq",
            "start": 5, "end": 5, "byte_order": "big", "scale": 1,
        },
        "set_waveform::OUT::amplitude": {
            "label": "set_waveform", "direction": "OUT", "param": "amplitude",
            "start": 6, "end": 6, "byte_order": "big", "scale": 255 / 3.3,
        },
        "set_waveform::OUT::offset": {
            "label": "set_waveform", "direction": "OUT", "param": "offset",
            "start": 7, "end": 7, "byte_order": "big", "scale": 255 / 3.3,
        },
        "channel0_reading::IN::voltage": {
            "label": "channel0_reading", "direction": "IN", "param": "voltage",
            "start": 5, "end": 6, "byte_order": "little", "scale": 4095 / 3.3,
        },
    }
    with open(DECIPHERED_FILE, "w") as f:
        json.dump(deciphered, f, indent=2)

    monitors = {
        "channel0_reading::IN::voltage": {
            "label": "channel0_reading", "direction": "IN", "param": "voltage",
            "start": 5, "end": 6, "byte_order": "little", "scale": 4095 / 3.3,
            "precision": None, "tolerance": 0.15,
        },
    }
    with open(MONITORS_FILE, "w") as f:
        json.dump(monitors, f, indent=2)

    psu_start = out_count + len(oscilloscope.VOLTAGES)
    psu.main()
    psu_end = psu_start + len(psu.VOLTAGES) + len(psu.CURRENTS) - 1

    print()
    print(f"Oscilloscope: indices 0-{psu_start - 1}, fully labeled/deciphered/watched.")
    print(f"PSU: indices {psu_start}-{psu_end}, completely unlabeled — use these live.")


if __name__ == "__main__":
    main()
