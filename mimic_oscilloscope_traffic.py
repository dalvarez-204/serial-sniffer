"""Writes synthetic capture records that mimic the real ESP32 oscilloscope
protocol (see instro_app_code.txt / oscilloscope_code.txt) directly into
capture_log.jsonl, so the analyzer/UI can be tested against a realistic
protocol without needing the physical device.

Frame (same on both sides of the real protocol):
    [0x7E START] [2-byte little-endian LENGTH] [PAYLOAD] [XOR checksum] [0x7F END]

Run this, then load the UI — it appends to whatever's already in
capture_log.jsonl rather than overwriting it.
"""

import json
import math
import time

START = 0x7E
END = 0x7F
CMD_GEN = 0x03
ADC_PACKET_TYPE = 0x01

CAPTURE_FILE = "capture_log.jsonl"


def jitter(raw: int, i: int, spread: int = 3) -> int:
    """A real 12-bit ADC never returns the same count 16 times in a row —
    this stands in for that sample-to-sample noise so the payload isn't just
    two bytes repeated, which is what a truly constant reading degenerates to."""
    ripple = round(spread * math.sin(i * 0.9 + raw))
    return max(0, min(4095, raw + ripple))


def xor_checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result


def build_frame(payload: bytes) -> bytes:
    length = len(payload).to_bytes(2, "little")
    checksum = xor_checksum(payload)
    return bytes([START]) + length + payload + bytes([checksum, END])


def to_255(voltage: float, vref: float = 3.3) -> int:
    return int((voltage * 255) / vref)


def to_4095(voltage: float, vref: float = 3.3) -> int:
    return int((voltage / vref) * 4095)


def build_gen_command(wave_type: int, freq: int, amplitude_v: float, offset_v: float) -> bytes:
    payload = bytes([CMD_GEN, wave_type, freq, to_255(amplitude_v), to_255(offset_v)])
    return build_frame(payload)


def build_adc_packet(channel: int, samples: list[int]) -> bytes:
    payload = bytes([ADC_PACKET_TYPE, channel])
    for s in samples:
        payload += bytes([s & 0xFF, s >> 8])
    return build_frame(payload)


def main():
    records = []
    t = time.time()

    # OUT: sweep amplitude so find_scaled_value has real variation to search against.
    # Ground truth: amplitude byte is at overall frame offset 6 (START, len_lo, len_hi,
    # cmd, wave, freq, [amp], offset, chk, END), scale = 255/3.3 ~= 77.27 (not a decimal scale).
    amplitudes = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]
    for amplitude in amplitudes:
        frame = build_gen_command(wave_type=0, freq=10, amplitude_v=amplitude, offset_v=0.0)
        records.append({"timestamp": t, "direction": "OUT", "data_hex": frame.hex()})
        t += 0.05

    # IN: channel 0 only — the real sketch also sends channel 1 (ADC_PIN_2)
    # back to back, but that doubles the message count for no benefit when
    # you're just eyeballing/parsing captures by hand, so it's left out here.
    # Ground truth: samples start at overall frame offset 5, little-endian
    # 16-bit, scale = 4095/3.3 ~= 1240.9 to go from volts to raw, or divide
    # raw by 4095 then multiply by 3.3 to go the other way.
    voltages = [0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0]
    for voltage in voltages:
        raw = to_4095(voltage)
        samples = [jitter(raw, i) for i in range(16)]
        frame = build_adc_packet(channel=0, samples=samples)
        records.append({"timestamp": t, "direction": "IN", "data_hex": frame.hex()})
        t += 0.05

    with open(CAPTURE_FILE, "a") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    print(f"Appended {len(records)} synthetic records to {CAPTURE_FILE}")
    print(f"OUT ground truth: amplitude sweep {amplitudes} (volts), byte offset 6, scale 255/3.3")
    print(f"IN ground truth: channel 0 only, voltage sweep {voltages} (volts), byte offset 5+ (little-endian), scale 4095/3.3")


if __name__ == "__main__":
    main()
