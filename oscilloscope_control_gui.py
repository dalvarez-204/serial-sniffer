"""Crappy little Tkinter GUI for pretending to be the oscilloscope host.

Grounded directly in instro_app_code.txt (the real host-side interpreter)
and oscilloscope_code.txt (the real ESP32 firmware, which is what
oscilloscope_firmware.ino in this repo already is — a straight copy). This
is the real-hardware counterpart to mimic_oscilloscope_traffic.py — running
this against real hardware generates actual USB traffic CLOAK can sniff live
via usbmon, instead of fabricated capture_log.jsonl records.

Frame: [0x7E START] [2-byte little-endian LENGTH] [PAYLOAD] [XOR checksum
of PAYLOAD] [0x7F END]. ADC packets: payload = [0x01 type][channel][16x
little-endian 12-bit samples]. Voltage = raw/4095 * 3.3 (12-bit ADC, vref
3.3V) — see voltage_extractor() in instro_app_code.txt. The waveform
generator command (CMD_GEN = 0x03) packs [wave_type, freq, amplitude_255,
offset_255], where amplitude/offset are volts scaled to a 0-255 DAC count
via to_255() (int(value * 255 / 3.3)) — the same convention used on both
ends of the real protocol.

Requires: pip install pyserial
"""

import collections
import queue
import sys
import threading
import time
import tkinter as tk

import serial

PORT = "/dev/ttyACM0"
BAUD = 115200

START = 0x7E
END = 0x7F
MAX_LEN = 256

CMD_START = 0x01  # ADC_STREAMING
CMD_STOP = 0x02
CMD_GEN = 0x03
CMD_GEN_OFF = 0x04

PKT_TYPE_ADC = 0x01

VREF = 3.3
ADC_MAX = 4095
WAVE_TYPES = {"Sine": 0x00, "Square": 0x01, "Triangle": 0x02}

GRAPH_WIDTH = 440
GRAPH_HEIGHT = 160
GRAPH_HISTORY_LEN = 200  # raw ADC samples per channel, not packets


def xor_checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result


def build_frame(cmd: int, args: list[int] | None = None) -> bytes:
    payload = bytes([cmd] + (args or []))
    length = len(payload)
    checksum = xor_checksum(payload)
    return bytes([START]) + length.to_bytes(2, "little") + payload + bytes([checksum, END])


def to_255(voltage_value: float) -> int:
    """Arduino operates using 255 as the 3.3V output for the DAC."""
    return max(0, min(255, int((voltage_value * 255) / VREF)))


def voltage_extractor(adc_signal: int) -> float:
    """Does the opposite of to_255 — turns a 12-bit ADC reading back into volts."""
    return (adc_signal / ADC_MAX) * VREF


class OscilloscopeGui:
    def __init__(self, root, ser):
        self.ser = ser
        self.root = root
        self.packets = queue.Queue()
        self.streaming = True

        root.title("Pretend oscilloscope control")

        self.wave_type_var = tk.StringVar(value="Sine")
        tk.Label(root, text="Waveform:").grid(row=0, column=0, padx=8, pady=8)
        tk.OptionMenu(root, self.wave_type_var, *WAVE_TYPES.keys()).grid(row=0, column=1, padx=8, pady=8)

        self.freq_entry = self._add_row(root, 1, "Frequency (arbitrary units):", "10")
        self.amp_entry = self._add_row(root, 2, "Amplitude (0-3.3V):", "1.0")
        self.offset_entry = self._add_row(root, 3, "Offset (0-3.3V):", "0.0")

        tk.Button(root, text="Send waveform", command=self.send_waveform).grid(row=4, column=0, padx=8, pady=8)
        tk.Button(root, text="Halt waveform", command=self.halt_waveform).grid(row=4, column=1, padx=8, pady=8)

        self.stream_button = tk.Button(root, text="Streaming: on", command=self.toggle_streaming)
        self.stream_button.grid(row=4, column=2, padx=8, pady=8)

        self.reading_label = tk.Label(root, text="CH1: -- V   CH2: -- V", font=("Courier", 14))
        self.reading_label.grid(row=5, column=0, columnspan=3, padx=8, pady=8)

        # rolling window of raw voltage samples per channel — a fixed 0-3.3V
        # axis (not autoscaled) since that's the ADC's actual full-scale
        # range, same as a real scope would show
        self.ch_history = {0: collections.deque(maxlen=GRAPH_HISTORY_LEN), 1: collections.deque(maxlen=GRAPH_HISTORY_LEN)}
        self.graph = tk.Canvas(root, width=GRAPH_WIDTH, height=GRAPH_HEIGHT, bg="black")
        self.graph.grid(row=6, column=0, columnspan=3, padx=8, pady=8)

        self.stop_event = threading.Event()
        threading.Thread(target=self.read_loop, daemon=True).start()
        self.root.after(50, self.poll_packets)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.ser.write(build_frame(CMD_START))  # match the real host's startup behavior

    def _add_row(self, root, row, label_text, default):
        tk.Label(root, text=label_text).grid(row=row, column=0, padx=8, pady=8)
        entry = tk.Entry(root)
        entry.insert(0, default)
        entry.grid(row=row, column=1, padx=8, pady=8)
        return entry

    def send_waveform(self):
        try:
            freq = int(self.freq_entry.get())
            amplitude = float(self.amp_entry.get())
            offset = float(self.offset_entry.get())
        except ValueError:
            return
        wave = WAVE_TYPES[self.wave_type_var.get()]
        self.ser.write(build_frame(CMD_GEN, [wave, freq, to_255(amplitude), to_255(offset)]))

    def halt_waveform(self):
        self.ser.write(build_frame(CMD_GEN_OFF))

    def toggle_streaming(self):
        self.streaming = not self.streaming
        self.ser.write(build_frame(CMD_START if self.streaming else CMD_STOP))
        self.stream_button.config(text=f"Streaming: {'on' if self.streaming else 'off'}")

    def read_loop(self):
        # mirrors the firmware's own read_packet() state machine exactly
        # (WAIT_START, READ_LEN, READ_PAYLOAD, READ_CHK, READ_END)
        state = "WAIT_START"
        length = 0
        len_bytes = bytearray()
        payload = bytearray()

        while not self.stop_event.is_set():
            byte = self.ser.read(1)
            if not byte:
                continue
            b = byte[0]

            if state == "WAIT_START":
                if b == START:
                    state = "READ_LEN"
                    len_bytes = bytearray()
            elif state == "READ_LEN":
                len_bytes.append(b)
                if len(len_bytes) == 2:
                    length = int.from_bytes(bytes(len_bytes), "little")
                    if length > MAX_LEN:
                        state = "WAIT_START"
                    else:
                        payload = bytearray()
                        state = "READ_PAYLOAD"
            elif state == "READ_PAYLOAD":
                payload.append(b)
                if len(payload) >= length:
                    state = "READ_CHK"
            elif state == "READ_CHK":
                state = "READ_END" if b == xor_checksum(bytes(payload)) else "WAIT_START"
            elif state == "READ_END":
                if b == END:
                    self._handle_packet(bytes(payload))
                state = "WAIT_START"

    def _handle_packet(self, payload):
        if len(payload) < 2 or payload[0] != PKT_TYPE_ADC:
            return
        channel = payload[1]
        samples = []
        for i in range(2, len(payload) - 1, 2):
            samples.append(payload[i] | (payload[i + 1] << 8))
        voltages = [voltage_extractor(s) for s in samples]
        self.packets.put((channel, voltages))

    def poll_packets(self):
        latest = {0: None, 1: None}
        try:
            while True:
                channel, voltages = self.packets.get_nowait()
                self.ch_history[channel].extend(voltages)
                if voltages:
                    latest[channel] = voltages[-1]
        except queue.Empty:
            pass
        if latest[0] is not None or latest[1] is not None:
            ch1_text = f"{latest[0]:.3f} V" if latest[0] is not None else "--"
            ch2_text = f"{latest[1]:.3f} V" if latest[1] is not None else "--"
            self.reading_label.config(text=f"CH1: {ch1_text}   CH2: {ch2_text}")
            self._draw_graph()
        self.root.after(50, self.poll_packets)

    def _draw_graph(self):
        self.graph.delete("all")
        self._draw_series(self.ch_history[0], "#4a9eff")
        self._draw_series(self.ch_history[1], "#ffa500")
        self.graph.create_text(8, 8, anchor="nw", text="CH1", fill="#4a9eff", font=("Courier", 9))
        self.graph.create_text(8, 22, anchor="nw", text="CH2", fill="#ffa500", font=("Courier", 9))

    def _draw_series(self, history, color):
        if len(history) < 2:
            return
        margin = 5
        step = GRAPH_WIDTH / (len(history) - 1)
        points = []
        for i, value in enumerate(history):
            x = i * step
            # fixed 0-VREF axis, not autoscaled — this is the ADC's actual
            # full-scale range, same as a real scope's fixed voltage divisions
            y = GRAPH_HEIGHT - margin - (value / VREF) * (GRAPH_HEIGHT - 2 * margin)
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
    OscilloscopeGui(root, ser)
    root.mainloop()


if __name__ == "__main__":
    main()
