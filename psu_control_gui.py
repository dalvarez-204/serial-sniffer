"""Crappy little Tkinter GUI for pretending to be a PSU host.

Sends real set_voltage/set_ocp/set_ovp commands over serial to an
Arduino/ESP32 running psu_firmware.ino, and displays the (voltage, current)
readings that come back. This is the real-hardware counterpart to
mimic_psu_traffic.py — running this generates actual USB traffic CLOAK can
sniff live via usbmon, instead of fabricated capture_log.jsonl records.

Requires: pip install pyserial
"""

import collections
import queue
import sys
import threading
import time
import tkinter as tk

import serial

GRAPH_WIDTH = 440
GRAPH_HEIGHT = 160
GRAPH_HISTORY_LEN = 100

PORT = "/dev/ttyACM0"
BAUD = 115200

STX = 0x02
ETX = 0x03
CMD_SET_VOLTAGE = 0x01
CMD_READING = 0x02
CMD_SET_OCP = 0x03
CMD_SET_OVP = 0x04

SCALE = 1000  # raw = round(value * SCALE) for every field — exact mV/mA resolution


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


class PsuGui:
    def __init__(self, root, ser):
        self.ser = ser
        self.root = root
        self.readings = queue.Queue()

        root.title("Pretend PSU control")

        self.voltage_entry = self._add_row(root, 0, "Set voltage (0-30V):", "0")
        tk.Button(root, text="Send", command=self.send_voltage).grid(row=0, column=2, padx=8, pady=8)

        self.ocp_entry = self._add_row(root, 1, "Set OCP limit (0-5A):", "5")
        tk.Button(root, text="Send", command=self.send_ocp).grid(row=1, column=2, padx=8, pady=8)

        self.ovp_entry = self._add_row(root, 2, "Set OVP limit (0-30V):", "30")
        tk.Button(root, text="Send", command=self.send_ovp).grid(row=2, column=2, padx=8, pady=8)

        self.reading_label = tk.Label(root, text="Reading: --", font=("Courier", 14))
        self.reading_label.grid(row=3, column=0, columnspan=3, padx=8, pady=8)

        # rolling window of recent readings, each series scaled to the
        # canvas independently since voltage (0-30V) and current (0-5A)
        # don't share a sensible y-axis
        self.voltage_history = collections.deque(maxlen=GRAPH_HISTORY_LEN)
        self.current_history = collections.deque(maxlen=GRAPH_HISTORY_LEN)
        self.graph = tk.Canvas(root, width=GRAPH_WIDTH, height=GRAPH_HEIGHT, bg="black")
        self.graph.grid(row=4, column=0, columnspan=3, padx=8, pady=8)

        self.stop_event = threading.Event()
        threading.Thread(target=self.read_loop, daemon=True).start()
        self.root.after(100, self.poll_readings)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _add_row(self, root, row, label_text, default):
        tk.Label(root, text=label_text).grid(row=row, column=0, padx=8, pady=8)
        entry = tk.Entry(root)
        entry.insert(0, default)
        entry.grid(row=row, column=1, padx=8, pady=8)
        return entry

    def _send_value(self, entry, cmd):
        try:
            value = float(entry.get())
        except ValueError:
            return
        self.ser.write(build_set_command(cmd, value))

    def send_voltage(self):
        self._send_value(self.voltage_entry, CMD_SET_VOLTAGE)

    def send_ocp(self):
        self._send_value(self.ocp_entry, CMD_SET_OCP)

    def send_ovp(self):
        self._send_value(self.ovp_entry, CMD_SET_OVP)

    def read_loop(self):
        # the board only ever sends the 8-byte CMD_READING frame back (2
        # bytes each for voltage and current), so this only needs to
        # recognize one fixed shape
        buf = bytearray()
        while not self.stop_event.is_set():
            byte = self.ser.read(1)
            if not byte:
                continue
            buf.append(byte[0])
            if len(buf) > 8:
                del buf[: len(buf) - 8]
            if (
                len(buf) == 8
                and buf[0] == STX
                and buf[7] == ETX
                and buf[1] == CMD_READING
                and buf[6] == xor_checksum(bytes(buf[1:6]))
            ):
                voltage = from_raw(int.from_bytes(buf[2:4], "big"))
                current = from_raw(int.from_bytes(buf[4:6], "big"))
                self.readings.put((voltage, current))
                buf.clear()

    def poll_readings(self):
        updated = False
        try:
            while True:
                voltage, current = self.readings.get_nowait()
                self.reading_label.config(text=f"Reading: {voltage:.3f} V, {current:.3f} A")
                self.voltage_history.append(voltage)
                self.current_history.append(current)
                updated = True
        except queue.Empty:
            pass
        if updated:
            self._draw_graph()
        self.root.after(100, self.poll_readings)

    def _draw_graph(self):
        self.graph.delete("all")
        self._draw_series(self.voltage_history, "#4a9eff")
        self._draw_series(self.current_history, "#ffa500")
        self.graph.create_text(8, 8, anchor="nw", text="voltage", fill="#4a9eff", font=("Courier", 9))
        self.graph.create_text(8, 22, anchor="nw", text="current", fill="#ffa500", font=("Courier", 9))

    def _draw_series(self, history, color):
        if len(history) < 2:
            return
        lo, hi = min(history), max(history)
        span = hi - lo or 1.0  # a flat line shouldn't divide by zero
        margin = 5
        step = GRAPH_WIDTH / (len(history) - 1)
        points = []
        for i, value in enumerate(history):
            x = i * step
            y = GRAPH_HEIGHT - margin - ((value - lo) / span) * (GRAPH_HEIGHT - 2 * margin)
            points.extend([x, y])
        self.graph.create_line(*points, fill=color, width=2)

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
