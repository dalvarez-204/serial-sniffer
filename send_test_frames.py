"""Sends synthetic framed messages over serial to test analyze_byte_variability.

Frame format:

    [0xAA START] [high byte] [low byte] [checksum] [0x55 END]

The 2-byte payload is a swept integer value (big-endian). The checksum is
XOR of the two payload bytes, so it's easy to hand-verify against whatever
the analyzer reports.

Requires: pip install pyserial
Run this while first.py's log_capture_to_file is capturing in another
terminal, and while the Arduino is running the echo sketch.
"""

import time

import serial

PORT = "/dev/ttyACM0"
BAUD = 115200

START_BYTE = 0xAA
END_BYTE = 0x55


def build_frame(value: int) -> bytes:
    high = (value >> 8) & 0xFF
    low = value & 0xFF
    checksum = high ^ low
    return bytes([START_BYTE, high, low, checksum, END_BYTE])


def main():
    ser = serial.Serial(PORT, BAUD, timeout=1)
    time.sleep(2)  # let the Arduino finish its reset-on-connect before sending

    for value in range(1, 11):
        frame = build_frame(value)
        print(f"sending value={value}: {frame.hex()}")
        ser.write(frame)
        time.sleep(0.5)

    ser.close()


if __name__ == "__main__":
    main()
