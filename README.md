# serial-sniffer

A protocol-learning dongle/toolkit: capture bidirectional serial traffic between a legacy/unknown instrument and its control software, let a user label command/response pairs, and generate an automation driver from the observed behavior — no protocol documentation required.

## Status

Early scoping. Current approach:

- For instruments that connect via a USB-to-serial adapter (FTDI/CH340/etc. — the common case for legacy bench gear), no custom hardware bridge is needed: Linux's `usbmon` + Wireshark/`tshark` can passively capture the USB bulk transfers (which are the raw serial bytes) directly on the host, without interfering with the vendor software's own connection to the device.
- Validated end-to-end on an Arduino running an echo sketch: captured traffic in Wireshark via `usbmon`, then confirmed a live extraction pipeline with `tshark -T fields` piped into Python.
- Custom microcontroller hardware (Teensy / RP2040 Pico) as a transparent UART↔USB bridge is still the fallback plan for instruments with **native USB** and no exposed UART to tap.

## Open problems

Once capture is solid, the harder part is inferring the protocol from observed traffic:

- **Framing & integrity** — start/end delimiters, fixed vs. variable length, checksum/CRC. Largely automatable by diffing many repeated captures of the same action.
- **Encoding** — endianness, numeric precision/type, scaling factor. Automatable by sweeping a known value and watching which bytes change and how.
- **Semantics/units** — does this field mean voltage, current, or resistance? Not inferable from bytes alone; needs active user labeling at capture time or a device/model lookup.
- **Session/liveness** — startup handshakes, heartbeat/keepalive polling, timeouts.

## Goal

Output a driver/automation script usable standalone or as a Nominal Connect integration (Command Registry + streamed channels), built from labeled capture data instead of hand-written protocol code.
