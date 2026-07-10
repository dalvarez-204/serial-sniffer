"""Crappy little Tkinter GUI for pretending to be a PSU host.

Sends real set_voltage commands over serial to an Arduino/ESP32 running
psu_firmware.ino, and displays whatever read_current frames come back. This
is the real-hardware counterpart to mimic_psu_traffic.py — running this
generates actual USB traffic CLOAK can sniff live via usbmon, instead of
fabricated capture_log.jsonl records.

Requires: pip install pyserial
"""

import queue
import sys
import threading
import time
import tkinter as tk

import serial

PORT = "/dev/ttyACM0"
BAUD = 115200

STX = 0x02
ETX = 0x03
CMD_SET_VOLTAGE = 0x01
CMD_READ_CURRENT = 0x02

VOLTAGE_VREF = 30.0
CURRENT_VREF = 5.0


def xor_checksum(cmd: int, value: int) -> int:
    return cmd ^ value


def to_byte(value: float, vref: float) -> int:
    return max(0, min(255, round((value * 255) / vref)))


def from_byte(raw: int, vref: float) -> float:
    return (raw * vref) / 255


def build_frame(cmd: int, value_byte: int) -> bytes:
    return bytes([STX, cmd, value_byte, xor_checksum(cmd, value_byte), ETX])


class PsuGui:
    def __init__(self, root, ser):
        self.ser = ser
        self.root = root
        self.readings = queue.Queue()

        root.title("Pretend PSU control")

        tk.Label(root, text="Set voltage (0-30V):").grid(row=0, column=0, padx=8, pady=8)
        self.voltage_entry = tk.Entry(root)
        self.voltage_entry.insert(0, "0")
        self.voltage_entry.grid(row=0, column=1, padx=8, pady=8)
        tk.Button(root, text="Send", command=self.send_voltage).grid(row=0, column=2, padx=8, pady=8)

        self.current_label = tk.Label(root, text="Current reading: --", font=("Courier", 14))
        self.current_label.grid(row=1, column=0, columnspan=3, padx=8, pady=8)

        self.stop_event = threading.Event()
        threading.Thread(target=self.read_loop, daemon=True).start()
        self.root.after(100, self.poll_readings)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

    def send_voltage(self):
        try:
            voltage = float(self.voltage_entry.get())
        except ValueError:
            return
        self.ser.write(build_frame(CMD_SET_VOLTAGE, to_byte(voltage, VOLTAGE_VREF)))

    def read_loop(self):
        buf = bytearray()
        while not self.stop_event.is_set():
            byte = self.ser.read(1)
            if not byte:
                continue
            buf.append(byte[0])
            if len(buf) > 5:
                del buf[: len(buf) - 5]
            if len(buf) == 5 and buf[0] == STX and buf[4] == ETX and buf[3] == xor_checksum(buf[1], buf[2]):
                if buf[1] == CMD_READ_CURRENT:
                    self.readings.put(from_byte(buf[2], CURRENT_VREF))
                buf.clear()

    def poll_readings(self):
        try:
            while True:
                current = self.readings.get_nowait()
                self.current_label.config(text=f"Current reading: {current:.3f} A")
        except queue.Empty:
            pass
        self.root.after(100, self.poll_readings)

    def on_close(self):
        self.stop_event.set()
        self.root.destroy()


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else PORT
    ser = serial.Serial(port, BAUD, timeout=0.2)
    time.sleep(2)  # let the board finish its reset-on-connect before sending
    root = tk.Tk()
    PsuGui(root, ser)
    root.mainloop()


if __name__ == "__main__":
    main()
