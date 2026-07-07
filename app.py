from flask import Flask, jsonify, request, render_template
import json
import os

from first import load_capture_log, analyze_byte_variability, find_checksum_range, find_scaled_value

app = Flask(__name__)

CAPTURE_FILE = "capture_log.jsonl"
LABELS_FILE = "labels.json"


def group_key(direction, length):
    return f"{direction}_{length}"


def build_capture_view(filepath):
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

    return messages_view, analysis


def load_labels():
    if os.path.exists(LABELS_FILE):
        with open(LABELS_FILE) as f:
            return json.load(f)
    return {}


def save_labels(labels):
    with open(LABELS_FILE, "w") as f:
        json.dump(labels, f, indent=2)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/messages")
def api_messages():
    if not os.path.exists(CAPTURE_FILE):
        return jsonify({"messages": [], "analysis": {}, "labels": {}})
    messages, analysis = build_capture_view(CAPTURE_FILE)
    return jsonify({"messages": messages, "analysis": analysis, "labels": load_labels()})


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
    }
    save_labels(labels)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True, port=5001)
