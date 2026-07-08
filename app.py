from flask import Flask, jsonify, request, render_template
import json
import os
import subprocess
import threading

from first import load_capture_log, analyze_byte_variability, find_checksum_range, find_scaled_value, stream_usb_capture

app = Flask(__name__)

CAPTURE_FILE = "capture_log.jsonl"
LABELS_FILE = "labels.json"
DECIPHERED_FILE = "deciphered.json"
CAPTURE_CONFIG_FILE = "capture_config.json"


def deciphered_key(label, direction):
    return f"{label}::{direction}"


def group_key(direction, length):
    return f"{direction}_{length}"


_capture_cache = {"key": None, "messages": None, "analysis": None}


def build_capture_view(filepath):
    stat = os.stat(filepath)
    cache_key = (stat.st_mtime_ns, stat.st_size)
    if _capture_cache["key"] == cache_key:
        return _capture_cache["messages"], _capture_cache["analysis"]

    records = list(load_capture_log(filepath))

    groups = {}
    for _, direction, data in records:
        key = group_key(direction, len(data))
        groups.setdefault(key, []).append(data)

    analysis = {}
    for key, messages in groups.items():
        variability = analyze_byte_variability(messages)
        checksum = None
        if len(messages) > 1 and len(messages[0]) >= 2:
            try:
                checksum = find_checksum_range(messages)
            except AssertionError:
                checksum = None
        analysis[key] = {
            "variability": variability,
            "checksum": checksum,
            "sample_count": len(messages),
        }

    messages_view = []
    for index, (timestamp, direction, data) in enumerate(records):
        messages_view.append({
            "index": index,
            "timestamp": timestamp,
            "direction": direction,
            "length": len(data),
            "hex_bytes": [f"{b:02x}" for b in data],
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
            "group_key": group_key(direction, len(data)),
        })

    _capture_cache["key"] = cache_key
    _capture_cache["messages"] = messages_view
    _capture_cache["analysis"] = analysis
    return messages_view, analysis


def load_labels():
    if os.path.exists(LABELS_FILE):
        with open(LABELS_FILE) as f:
            return json.load(f)
    return {}


def save_labels(labels):
    with open(LABELS_FILE, "w") as f:
        json.dump(labels, f, indent=2)


def load_capture_config():
    defaults = {"interface": "usbmon3", "device_address": 2}
    if os.path.exists(CAPTURE_CONFIG_FILE):
        with open(CAPTURE_CONFIG_FILE) as f:
            defaults.update(json.load(f))
    return defaults


def save_capture_config(config):
    with open(CAPTURE_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def load_deciphered():
    if os.path.exists(DECIPHERED_FILE):
        with open(DECIPHERED_FILE) as f:
            return json.load(f)
    return {}


def save_deciphered(deciphered):
    with open(DECIPHERED_FILE, "w") as f:
        json.dump(deciphered, f, indent=2)


# tshark runs continuously in the background once enabled; "enabled" only
# gates whether incoming records get written to disk. This sidesteps
# starting/stopping the subprocess on every toggle click. The one thing that
# does need a restart is the interface/device_address themselves, since
# those are baked into the tshark command at launch.
capture_state = {"thread": None, "process_holder": {}, "enabled": False, "running": False}


def _capture_loop(interface, device_address):
    capture_state["process_holder"] = {}
    capture_state["running"] = True
    try:
        for timestamp, direction, data in stream_usb_capture(interface, device_address, capture_state["process_holder"]):
            if not capture_state["enabled"]:
                continue
            record = {"timestamp": timestamp, "direction": direction, "data_hex": data.hex()}
            # reopen per write (not one long-held handle) so a "Clear all captures"
            # delete while this thread is running doesn't leave us writing to an
            # unlinked inode nothing can see
            with open(CAPTURE_FILE, "a") as f:
                f.write(json.dumps(record) + "\n")
    finally:
        capture_state["running"] = False


def _start_capture_thread():
    config = load_capture_config()
    thread = threading.Thread(
        target=_capture_loop,
        args=(config["interface"], config["device_address"]),
        daemon=True,
    )
    capture_state["thread"] = thread
    thread.start()


def _stop_capture_thread():
    holder = capture_state.get("process_holder") or {}
    proc = holder.get("proc")
    if proc is not None:
        holder["stopped_intentionally"] = True
        proc.terminate()
    thread = capture_state.get("thread")
    if thread is not None:
        thread.join(timeout=5)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/messages")
def api_messages():
    if not os.path.exists(CAPTURE_FILE):
        return jsonify({"messages": [], "analysis": {}, "labels": {}, "deciphered": load_deciphered()})
    messages, analysis = build_capture_view(CAPTURE_FILE)
    return jsonify({
        "messages": messages,
        "analysis": analysis,
        "labels": load_labels(),
        "deciphered": load_deciphered(),
    })


@app.route("/api/capture", methods=["DELETE"])
def api_clear_capture():
    if os.path.exists(CAPTURE_FILE):
        os.remove(CAPTURE_FILE)
    if os.path.exists(LABELS_FILE):
        os.remove(LABELS_FILE)
    _capture_cache["key"] = None
    _capture_cache["messages"] = None
    _capture_cache["analysis"] = None
    return jsonify({"ok": True})


@app.route("/api/capture_config", methods=["GET"])
def api_get_capture_config():
    return jsonify(load_capture_config())


@app.route("/api/capture_config", methods=["POST"])
def api_save_capture_config():
    payload = request.get_json()
    config = {
        "interface": payload.get("interface") or "usbmon3",
        "device_address": int(payload.get("device_address") or 2),
    }
    save_capture_config(config)
    if capture_state["running"]:
        _stop_capture_thread()
        _start_capture_thread()
    return jsonify({"ok": True})


@app.route("/api/capture/enable", methods=["POST"])
def api_enable_capture():
    capture_state["enabled"] = True
    if not capture_state["running"]:
        _start_capture_thread()
    return jsonify({"ok": True})


@app.route("/api/capture/disable", methods=["POST"])
def api_disable_capture():
    capture_state["enabled"] = False
    return jsonify({"ok": True})


@app.route("/api/capture/status")
def api_capture_status():
    holder = capture_state.get("process_holder") or {}
    return jsonify({
        "enabled": capture_state["enabled"],
        "running": capture_state["running"],
        "error": holder.get("error"),
    })


@app.route("/api/lsusb")
def api_lsusb():
    try:
        result = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        return jsonify({"output": result.stdout or result.stderr})
    except FileNotFoundError:
        return jsonify({"output": "lsusb not found on this machine."})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "lsusb timed out."})


@app.route("/api/label/<int:index>", methods=["DELETE"])
def api_delete_label(index):
    labels = load_labels()
    labels.pop(str(index), None)
    save_labels(labels)
    return jsonify({"ok": True})


@app.route("/api/find_value", methods=["POST"])
def api_find_value():
    payload = request.get_json()
    indices = payload["indices"]
    expected_values = payload["expected_values"]
    tolerance = payload.get("tolerance", 0)
    scales = payload.get("scales")
    span = tuple(payload["span"]) if payload.get("span") else None

    if not os.path.exists(CAPTURE_FILE):
        return jsonify({"matches": []})

    records = list(load_capture_log(CAPTURE_FILE))
    messages = [records[i][2] for i in indices]

    matches = find_scaled_value(messages, expected_values, tolerance, scales, span)
    return jsonify({"matches": matches})


@app.route("/api/label", methods=["POST"])
def api_label():
    payload = request.get_json()
    index = str(payload["index"])
    labels = load_labels()
    labels[index] = {
        "name": payload.get("name", ""),
        "note": payload.get("note", ""),
        "value": payload.get("value"),
    }
    save_labels(labels)
    return jsonify({"ok": True})


@app.route("/api/deciphered", methods=["POST"])
def api_save_deciphered():
    payload = request.get_json()
    key = deciphered_key(payload["label"], payload["direction"])
    deciphered = load_deciphered()
    deciphered[key] = {
        "label": payload["label"],
        "direction": payload["direction"],
        "start": payload["start"],
        "end": payload["end"],
        "byte_order": payload["byte_order"],
        "scale": payload["scale"],
    }
    save_deciphered(deciphered)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # use_reloader=False: the reloader restarts the whole process on file
    # changes, which would silently orphan the background capture thread
    app.run(debug=True, port=5001, use_reloader=False)
