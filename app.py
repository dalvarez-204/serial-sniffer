from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template
import json
import logging
import os
import subprocess
import threading

from first import load_capture_log, analyze_byte_variability, find_checksum_range, find_scaled_value, stream_usb_capture, FrameReassembler
from codegen import build_codegen_context, generate_driver_code, generate_full_driver_code
from line_coding import capture_line_coding

load_dotenv()

app = Flask(__name__)


class SuppressGetRequestsFilter(logging.Filter):
    """Keeps POST/DELETE requests visible in the terminal, but drops the
    constant GET spam from message/status polling."""

    def filter(self, record):
        return "GET" not in record.getMessage()


logging.getLogger("werkzeug").addFilter(SuppressGetRequestsFilter())

CAPTURE_FILE = "capture_log.jsonl"
LABELS_FILE = "labels.json"
DECIPHERED_FILE = "deciphered.json"
CAPTURE_CONFIG_FILE = "capture_config.json"
MONITORS_FILE = "monitors.json"


def deciphered_key(label, direction, param):
    return f"{label}::{direction}::{param}"


def group_key(direction, length):
    return f"{direction}_{length}"


_capture_cache = {"key": None, "messages": None, "analysis": None}


def build_capture_view(filepath):
    stat = os.stat(filepath)
    cache_key = (stat.st_mtime_ns, stat.st_size)
    if _capture_cache["key"] == cache_key:
        return _capture_cache["messages"], _capture_cache["analysis"]

    records = list(load_capture_log(filepath))
    # tshark can emit a record with usb.data_len > 0 but no actual capdata
    # (e.g. some control transfers) — those decode to zero-length messages
    # that have nothing to show or analyze, so drop them before indexing
    records = [r for r in records if len(r[3]) > 0]

    groups = {}
    for _, _, direction, data in records:
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
    for seq, timestamp, direction, data in records:
        messages_view.append({
            # a permanent identity, not a position — stays the same for this
            # message even after older ones get trimmed out of the buffer
            "index": seq,
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
    defaults = {
        "interface": "usbmon3",
        "device_address": 2,
        # frame reassembly is opt-in — a None start byte means "off", every
        # USB transfer is treated as its own message (existing behavior,
        # correct for the vast majority of protocols that don't span
        # multiple USB transfers per logical message)
        "reassembly_start_byte": None,
        "reassembly_length_offset": 1,
        "reassembly_length_size": 2,
        "reassembly_length_order": "little",
        "reassembly_trailing_bytes": 2,
    }
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


def load_monitors():
    if os.path.exists(MONITORS_FILE):
        with open(MONITORS_FILE) as f:
            return json.load(f)
    return {}


def save_monitors(monitors):
    with open(MONITORS_FILE, "w") as f:
        json.dump(monitors, f, indent=2)


def _purge_deciphered_and_monitors(name, direction):
    """Removes every deciphered field and monitor for this label+direction.
    Only call this once NO message carries the label anymore — otherwise
    this deletes byte-range knowledge that's still valid for whichever
    messages still have it."""
    deciphered = load_deciphered()
    pruned_deciphered = {k: v for k, v in deciphered.items() if not (v["label"] == name and v["direction"] == direction)}
    if len(pruned_deciphered) != len(deciphered):
        save_deciphered(pruned_deciphered)

    monitors = load_monitors()
    pruned_monitors = {k: v for k, v in monitors.items() if not (v["label"] == name and v["direction"] == direction)}
    if len(pruned_monitors) != len(monitors):
        save_monitors(pruned_monitors)


# tshark runs continuously in the background once enabled; "enabled" only
# gates whether incoming records get written to disk. This sidesteps
# starting/stopping the subprocess on every toggle click. The one thing that
# does need a restart is the interface/device_address themselves, since
# those are baked into the tshark command at launch.
capture_state = {"thread": None, "process_holder": {}, "enabled": False, "running": False, "next_seq": 0}

MAX_CAPTURE_MESSAGES = 300


def _trim_capture_log():
    """Keeps the capture log bounded to the last MAX_CAPTURE_MESSAGES
    UNLABELED messages, so a long-running live capture doesn't grow the file
    (and the in-browser table) without limit — but a labeled message is
    never dropped, no matter how old, since it represents solved/important
    work. Each record's "seq" (see load_capture_log) is its permanent
    identity, so trimming never changes what any surviving message is
    called. Since only unlabeled messages are ever dropped, there's nothing
    to prune from labels.json — a dropped message never had a label."""
    if not os.path.exists(CAPTURE_FILE):
        return
    raw_records = list(load_capture_log(CAPTURE_FILE))
    filtered = [r for r in raw_records if len(r[3]) > 0]
    if len(filtered) <= MAX_CAPTURE_MESSAGES:
        return

    labels = load_labels()

    def is_labeled(record):
        return bool(labels.get(str(record[0]), {}).get("name"))

    recent = filtered[-MAX_CAPTURE_MESSAGES:]
    older = filtered[:-MAX_CAPTURE_MESSAGES]
    protected_older = [r for r in older if is_labeled(r)]
    dropped = [r for r in older if not is_labeled(r)]
    if not dropped:
        return  # every older message is labeled — nothing left to trim

    kept = sorted(protected_older + recent, key=lambda r: r[0])
    with open(CAPTURE_FILE, "w") as f:
        for seq, timestamp, direction, data in kept:
            f.write(json.dumps({"seq": seq, "timestamp": timestamp, "direction": direction, "data_hex": data.hex()}) + "\n")


def _next_capture_seq():
    """The next permanent message id to stamp on a newly captured record —
    continues from whatever's already in the log (inferring fallback seq
    for older records that predate this field) instead of restarting at 0
    and colliding with messages already on screen."""
    if not os.path.exists(CAPTURE_FILE):
        return 0
    max_seq = -1
    for seq, _, _, _ in load_capture_log(CAPTURE_FILE):
        max_seq = max(max_seq, seq)
    return max_seq + 1


def _capture_loop(interface, device_address):
    capture_state["process_holder"] = {}
    capture_state["running"] = True
    # lives in capture_state (not a local variable) so "Clear all captures"
    # can reset it back to 0 for a real fresh start, without needing to
    # restart this thread — trimming the buffer, in contrast, never resets it
    capture_state["next_seq"] = _next_capture_seq()

    config = load_capture_config()
    reassembler = None
    if config.get("reassembly_start_byte") is not None:
        reassembler = FrameReassembler(
            start_byte=config["reassembly_start_byte"],
            length_field_offset=config["reassembly_length_offset"],
            length_field_size=config["reassembly_length_size"],
            length_field_order=config["reassembly_length_order"],
            trailing_bytes=config["reassembly_trailing_bytes"],
        )

    try:
        for timestamp, direction, data in stream_usb_capture(interface, device_address, capture_state["process_holder"]):
            if not capture_state["enabled"]:
                if reassembler:
                    # don't let a paused/resumed capture merge stale
                    # partial bytes from before the pause with new ones
                    reassembler.buffers.clear()
                continue

            frames = reassembler.feed(direction, data) if reassembler else [data]
            for frame in frames:
                record = {
                    "seq": capture_state["next_seq"],
                    "timestamp": timestamp,
                    "direction": direction,
                    "data_hex": frame.hex(),
                }
                capture_state["next_seq"] += 1
                # reopen per write (not one long-held handle) so a "Clear all captures"
                # delete while this thread is running doesn't leave us writing to an
                # unlinked inode nothing can see
                with open(CAPTURE_FILE, "a") as f:
                    f.write(json.dumps(record) + "\n")
                _trim_capture_log()
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
        return jsonify({"messages": [], "analysis": {}, "labels": {}, "deciphered": load_deciphered(), "monitors": load_monitors()})
    messages, analysis = build_capture_view(CAPTURE_FILE)
    return jsonify({
        "messages": messages,
        "analysis": analysis,
        "labels": load_labels(),
        "deciphered": load_deciphered(),
        "monitors": load_monitors(),
    })


@app.route("/api/capture", methods=["DELETE"])
def api_clear_capture():
    if os.path.exists(CAPTURE_FILE):
        os.remove(CAPTURE_FILE)
    if os.path.exists(LABELS_FILE):
        os.remove(LABELS_FILE)
    capture_state["next_seq"] = 0  # a real fresh start, unlike buffer trimming which never resets this
    _capture_cache["key"] = None
    _capture_cache["messages"] = None
    _capture_cache["analysis"] = None
    return jsonify({"ok": True})


@app.route("/api/instrument", methods=["DELETE"])
def api_new_instrument():
    """A full reset for starting on a different device: unlike "Clear all
    captures" (which leaves deciphered/watched fields alone, for re-capturing
    the SAME instrument's traffic without losing already-solved work), this
    also wipes deciphered.json and monitors.json — leftover fields from a
    previous instrument have no reason to apply to a new one."""
    for path in (CAPTURE_FILE, LABELS_FILE, DECIPHERED_FILE, MONITORS_FILE):
        if os.path.exists(path):
            os.remove(path)
    capture_state["next_seq"] = 0
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
    reassembly_start_byte = payload.get("reassembly_start_byte")
    config = {
        "interface": payload.get("interface") or "usbmon3",
        "device_address": int(payload.get("device_address") or 2),
        "reassembly_start_byte": int(reassembly_start_byte) if reassembly_start_byte is not None else None,
        "reassembly_length_offset": int(payload.get("reassembly_length_offset") or 1),
        "reassembly_length_size": int(payload.get("reassembly_length_size") or 2),
        "reassembly_length_order": payload.get("reassembly_length_order") or "little",
        "reassembly_trailing_bytes": int(payload.get("reassembly_trailing_bytes") or 2),
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


@app.route("/api/detect_line_coding", methods=["POST"])
def api_detect_line_coding():
    config = load_capture_config()
    payload = request.get_json(silent=True) or {}
    interface = payload.get("interface") or config["interface"]
    device_address = int(payload.get("device_address") or config["device_address"])

    settings = capture_line_coding(interface, device_address, timeout=15.0)
    if settings is None:
        return jsonify({
            "ok": False,
            "error": "No SET_LINE_CODING request seen in 15s — reconnect (or re-run) the device's "
                     "original control software while this is running, then try again.",
        })
    return jsonify({"ok": True, "settings": settings})


@app.route("/api/label/<int:index>", methods=["DELETE"])
def api_delete_label(index):
    labels = load_labels()
    removed = labels.pop(str(index), None)
    save_labels(labels)

    # deciphered fields/monitors are keyed by label name, not message index —
    # if this was the last message carrying this label+direction, clean
    # those up too, otherwise they linger as orphaned "already deciphered"
    # data with no message to actually back it
    if removed and removed.get("name") and os.path.exists(CAPTURE_FILE):
        direction_by_seq = {seq: d for seq, _, d, data in load_capture_log(CAPTURE_FILE) if len(data) > 0}
        direction = direction_by_seq.get(index)
        if direction is not None:
            still_used = any(
                l.get("name") == removed["name"] and direction_by_seq.get(int(k)) == direction
                for k, l in labels.items()
            )
            if not still_used:
                _purge_deciphered_and_monitors(removed["name"], direction)

    return jsonify({"ok": True})


@app.route("/api/labels_by_name", methods=["DELETE"])
def api_delete_labels_by_name():
    """Removes a label from every message in its group at once — the Label
    groups panel's bulk "Remove label" action, instead of clearing messages
    one at a time."""
    payload = request.get_json()
    name = payload["name"]
    direction = payload["direction"]
    labels = load_labels()
    if not os.path.exists(CAPTURE_FILE):
        return jsonify({"ok": True, "removed": 0})

    direction_by_seq = {seq: d for seq, _, d, data in load_capture_log(CAPTURE_FILE) if len(data) > 0}
    to_remove = [
        key for key, label in labels.items()
        if label.get("name") == name and direction_by_seq.get(int(key)) == direction
    ]
    for key in to_remove:
        labels.pop(key, None)
    save_labels(labels)
    # this removes every instance of the label at once, so — unlike the
    # single-message delete above — it's always safe to also clean up its
    # deciphered fields/monitors here, no "is it still used elsewhere" check needed
    _purge_deciphered_and_monitors(name, direction)
    return jsonify({"ok": True, "removed": len(to_remove)})


@app.route("/api/consolidate_labels", methods=["POST"])
def api_consolidate_labels():
    """Merges several labels that turned out to be different fields of the
    SAME message into one — e.g. "get_voltage" and "get_current" discovered
    to actually be two byte ranges within a single frame. Renames every
    matching message's label and re-keys every deciphered field and monitor
    under the new name, instead of losing that work."""
    payload = request.get_json()
    names = set(payload["names"])
    direction = payload["direction"]
    new_name = payload["new_name"].strip()
    if not new_name:
        return jsonify({"error": "new name can't be empty"}), 400
    if len(names) < 2:
        return jsonify({"error": "need at least two labels to consolidate"}), 400

    direction_by_seq = {}
    if os.path.exists(CAPTURE_FILE):
        direction_by_seq = {seq: d for seq, _, d, data in load_capture_log(CAPTURE_FILE) if len(data) > 0}

    labels = load_labels()
    relabeled = 0
    for key, label in labels.items():
        if label.get("name") in names and direction_by_seq.get(int(key)) == direction:
            label["name"] = new_name
            relabeled += 1
    save_labels(labels)

    def rekey(store):
        moved = 0
        rekeyed = {}
        for key, entry in store.items():
            if entry["label"] in names and entry["direction"] == direction:
                entry = {**entry, "label": new_name}
                rekeyed[deciphered_key(new_name, direction, entry["param"])] = entry
                moved += 1
            else:
                rekeyed[key] = entry
        return rekeyed, moved

    new_deciphered, moved_deciphered = rekey(load_deciphered())
    save_deciphered(new_deciphered)

    new_monitors, moved_monitors = rekey(load_monitors())
    save_monitors(new_monitors)

    return jsonify({
        "ok": True,
        "relabeled": relabeled,
        "moved_deciphered": moved_deciphered,
        "moved_monitors": moved_monitors,
    })


@app.route("/api/find_value", methods=["POST"])
def api_find_value():
    payload = request.get_json()
    # bytes come straight from the browser's own Analysis panel, not re-derived
    # from a message index against the current capture log — a message's
    # index isn't a stable identity once the capture buffer can trim/re-index
    # older messages out from under an in-progress analysis
    messages = [bytes.fromhex(h) for h in payload["messages_hex"]]
    expected_values = payload["expected_values"]
    tolerance = payload.get("tolerance", 0)
    scales = payload.get("scales")
    span = tuple(payload["span"]) if payload.get("span") else None
    min_value = payload.get("min_value")
    if min_value is None:
        min_value = 0
    max_value = payload.get("max_value")
    byte_order = payload.get("byte_order")

    result = find_scaled_value(messages, expected_values, tolerance, scales, span, min_value, max_value, byte_order)
    return jsonify(result)


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
    key = deciphered_key(payload["label"], payload["direction"], payload["param"])
    deciphered = load_deciphered()
    deciphered[key] = {
        "label": payload["label"],
        "direction": payload["direction"],
        "param": payload["param"],
        "start": payload["start"],
        "end": payload["end"],
        "byte_order": payload["byte_order"],
        "scale": payload["scale"],
    }
    save_deciphered(deciphered)
    return jsonify({"ok": True})


@app.route("/api/monitors", methods=["POST"])
def api_save_monitor():
    payload = request.get_json()
    key = deciphered_key(payload["label"], payload["direction"], payload["param"])
    monitors = load_monitors()
    monitors[key] = {
        "label": payload["label"],
        "direction": payload["direction"],
        "param": payload["param"],
        "start": payload["start"],
        "end": payload["end"],
        "byte_order": payload["byte_order"],
        "scale": payload["scale"],
        "precision": payload.get("precision"),
        # no fixed baseline here — each message is checked against its own
        # label's param value, so the watch only "activates" once a message
        # has both the matching label and that param's value entered
        "tolerance": payload.get("tolerance", 0),
    }
    save_monitors(monitors)
    return jsonify({"ok": True})


@app.route("/api/monitors", methods=["DELETE"])
def api_delete_monitor():
    payload = request.get_json()
    key = deciphered_key(payload["label"], payload["direction"], payload["param"])
    monitors = load_monitors()
    monitors.pop(key, None)
    save_monitors(monitors)
    return jsonify({"ok": True})


@app.route("/api/generate_driver", methods=["POST"])
def api_generate_driver():
    payload = request.get_json()
    label = payload["label"]
    direction = payload["direction"]

    if not os.path.exists(CAPTURE_FILE):
        return jsonify({"error": "no capture data yet"}), 400

    records = list(load_capture_log(CAPTURE_FILE))
    _, analysis = build_capture_view(CAPTURE_FILE)
    deciphered_fields = [
        d for d in load_deciphered().values()
        if d["label"] == label and d["direction"] == direction
    ]
    if not deciphered_fields:
        return jsonify({"error": "no deciphered parameters for this label/direction yet"}), 400

    context = build_codegen_context(label, direction, deciphered_fields, records, analysis, load_labels())
    if context is None:
        return jsonify({"error": f'no "{direction}" messages found for label "{label}"'}), 400

    try:
        code, is_mock = generate_driver_code(context)
    except Exception as e:
        # without this, an exception here (missing dependency, network
        # error, bad API key) returns Flask's HTML error page, which the
        # frontend's res.json() then fails to parse — silently leaving the
        # "Generating..." placeholder stuck forever with no visible error
        return jsonify({"error": f"driver generation failed: {e}"}), 500
    return jsonify({"code": code, "mock": is_mock})


@app.route("/api/generate_full_driver", methods=["POST"])
def api_generate_full_driver():
    """Spans every currently-deciphered label into one combined driver class
    (poll/send/Nominal-publish), instead of one label+direction at a time."""
    if not os.path.exists(CAPTURE_FILE):
        return jsonify({"error": "no capture data yet"}), 400

    records = list(load_capture_log(CAPTURE_FILE))
    _, analysis = build_capture_view(CAPTURE_FILE)

    try:
        code, warnings, is_mock = generate_full_driver_code(records, analysis, load_deciphered(), load_labels())
    except Exception as e:
        return jsonify({"error": f"full driver generation failed: {e}"}), 500

    if code is None:
        return jsonify({"error": warnings[0] if warnings else "nothing to generate"}), 400

    return jsonify({"code": code, "warnings": warnings, "mock": is_mock})


if __name__ == "__main__":
    # use_reloader=False: the reloader restarts the whole process on file
    # changes, which would silently orphan the background capture thread
    # threaded=True: a slow/blocked driver-generation call (an LLM request)
    # would otherwise stall every other request — capture polling included
    app.run(debug=True, port=5001, use_reloader=False, threaded=True)
