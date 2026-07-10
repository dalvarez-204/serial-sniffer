"""Decodes the USB CDC-ACM SET_LINE_CODING control request — the message a
serial-over-USB device's host software sends once at connect time to
establish baud rate/byte size/parity/stop bits. This is a genuinely separate
capture concern from the rest of the tool: line coding rides on a CONTROL
transfer to endpoint 0, not the bulk IN/OUT endpoints stream_usb_capture()
(first.py) watches for the actual serial payload bytes.

CDC1.2 spec, SET_LINE_CODING (bRequest 0x20) data stage, 7 bytes:
    dwDTERate   (4 bytes, little-endian) — baud rate
    bCharFormat (1 byte)  — 0 = 1 stop bit, 1 = 1.5, 2 = 2
    bParityType (1 byte)  — 0 = none, 1 = odd, 2 = even, 3 = mark, 4 = space
    bDataBits   (1 byte)  — 5, 6, 7, 8, or 16

Note: I couldn't verify the exact tshark field names below against a real
capture (no tshark/USB hardware available while writing this) — `usb.capdata`
is the same field the rest of this tool already relies on for bulk transfers,
but `usb.setup.bRequest` is new here. If it comes back empty on your machine,
run:
    tshark -G fields | grep -i "usb.setup"
and adjust SET_LINE_CODING_FILTER accordingly.

Only baud rate/byte size/parity/stop bits are recoverable this way — flow
control settings (xonxoff/rtscts/dsrdtr) aren't wire-transmitted values at
all, they're host-driver behaviors, so there's nothing analogous to capture
for those.
"""

import select
import subprocess
import time

SET_LINE_CODING_REQUEST = 0x20

_CHAR_FORMAT = {0: 1, 1: 1.5, 2: 2}
_PARITY = {0: "none", 1: "odd", 2: "even", 3: "mark", 4: "space"}


def parse_line_coding(data: bytes) -> dict:
    if len(data) < 7:
        raise ValueError(f"SET_LINE_CODING payload should be 7 bytes, got {len(data)}")
    baudrate = int.from_bytes(data[0:4], "little")
    stopbits = _CHAR_FORMAT.get(data[4], data[4])
    parity = _PARITY.get(data[5], data[5])
    bytesize = data[6]
    return {"baudrate": baudrate, "bytesize": bytesize, "parity": parity, "stopbits": stopbits}


def capture_line_coding(interface: str, device_address: int, timeout: float = 15.0) -> dict | None:
    """Watches for a SET_LINE_CODING control transfer to the given device and
    returns the decoded settings, or None if nothing showed up within
    `timeout` seconds. The host software normally only sends this once, right
    when it opens the port — reconnect (or re-run) it while this is running
    to actually catch it."""
    cmd = [
        "tshark", "-i", interface, "-l",
        "-Y", f"usb.device_address == {device_address} && usb.setup.bRequest == {SET_LINE_CODING_REQUEST}",
        "-T", "fields",
        "-e", "usb.capdata",
        "-E", "separator=,",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([proc.stdout], [], [], remaining)
            if not ready:
                break
            line = proc.stdout.readline()
            if not line:
                break  # tshark exited
            hex_str = line.strip().replace(":", "")
            if not hex_str:
                continue
            try:
                data = bytes.fromhex(hex_str)
            except ValueError:
                continue
            if len(data) >= 7:
                return parse_line_coding(data)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    return None
