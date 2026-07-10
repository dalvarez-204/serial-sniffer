import subprocess
import json
import sys

def stream_usb_capture(interface: str, device_address: int, process_holder: dict | None = None):
    cmd = [
        "tshark", "-i", interface, "-l",
        "-Y", f"usb.device_address == {device_address} && usb.data_len > 0",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "usb.endpoint_address",
        "-e", "usb.capdata",
        "-E", "separator=,",
    ]

    # spawn the subprocess now :))))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1) # PIPE captures tshark's output
    if process_holder is not None:
        process_holder["proc"] = proc
    # text=True decodes output as text automatically, is this what we really want?
    for line in proc.stdout:
        timestamp_str, endpoint_str, capdata_str = line.strip().split(",")

        timestamp = float(timestamp_str)
        direction = "IN" if int(endpoint_str, 16) & 0x80 else "OUT"
        data = bytes.fromhex(capdata_str.replace(":", ""))
        yield timestamp, direction, data

    # loop only ends when tshark's stdout closes — either we terminated it on
    # purpose (process_holder["stopped_intentionally"]) or it died on its own
    proc.wait()
    if process_holder is not None and proc.returncode != 0 and not process_holder.get("stopped_intentionally"):
        process_holder["error"] = proc.stderr.read()

def log_capture_to_file(interface: str, device_address: int, filepath: str):
    """ captures all of our information for the JSON file, which we will use as 
    'context' to help inform our future moves """
    with open(filepath, "w") as f: 
        for timestamp, direction, data in stream_usb_capture(interface, device_address):
            record = {
                "timestamp": timestamp, 
                "direction": direction,
                "data_hex": data.hex(),
            }
            f.write(json.dumps(record) + "\n")
            f.flush()

def load_capture_log(filepath: str):
    """Yields (seq, timestamp, direction, data) for every record. "seq" is a
    permanent message identity that survives the capture buffer trimming
    older messages out — unlike a plain positional index, it never shifts
    for a message that's still around. Older records written before this
    field existed don't have one on disk; those get a fallback inferred by
    counting non-zero-length records seen so far, which reproduces the old
    enumerate-after-filtering behavior exactly (zero-length control-transfer
    records are always dropped before "index" is shown anywhere, so their
    own fallback value is never actually seen)."""
    next_fallback_seq = 0
    with open(filepath) as f:
        for line in f:
            record = json.loads(line)
            data = bytes.fromhex(record["data_hex"])
            seq = record.get("seq")
            if seq is None:
                seq = next_fallback_seq
                if len(data) > 0:
                    next_fallback_seq += 1
            else:
                next_fallback_seq = max(next_fallback_seq, seq + 1)
            yield seq, record["timestamp"], record["direction"], data

def analyze_byte_variability(messages: list[bytes]):
    """ takes the messages and checks if they are fixed-length bitstrings,
     'messages' is meant to be a batch of related captures, like all 10 responses """
    lengths = {len(m) for m in messages}
    if len(lengths) > 1: 
        return {"error": "messages have inconsistent lengths", "lengths": lengths}
    length = lengths.pop()
    results = []
    for offset in range(length):
        values = {message[offset] for message in messages}
        results.append({
            "offset": offset,
            "constant": len(values) ==1, # this should help give us a clue if it is start / end byte
            # or if it is a protocol specifier
            "values": sorted(values), 
            # each 'value' represents a byte that was sent,
            # so this is not super descriptive if a number spans several bytes!
        })
    return results

def xor_checksum(data: bytes) -> int: 
    result = 0
    for byte in data:
        result ^= byte
    return result

def sum_checksum(data:bytes)-> int:
    return sum(data) % 256


# let's get some dynamic programming in here!!!!

def find_checksum_range(messages: list[bytes], checksum_offset: int | None = None, end_offset: int | None = None) -> dict | None:
    length = len(messages[0])
    if end_offset is None:
        end_offset = length -1
    if checksum_offset is None:
        checksum_offset = length-2

    end_values = {m[end_offset] for m in messages}
    assert len(end_values)==1, "end byte isn't constant across messages"

    for algo_name, combine, identity in [
        ("xor", lambda a,b: a ^ b, 0),
        ("sum_mod_256", lambda a,b: (a+b) %256, 0)
    ]:
        prefixes = []
        for m in messages:
            prefix = [identity]
            for byte in m[:checksum_offset]:
                prefix.append(combine(prefix[-1], byte))
            prefixes.append(prefix)
        
        for start in range(checksum_offset):
            if algo_name=="xor":
                predicted = [prefixes[i][checksum_offset] ^ prefixes[i][start] for i in range(len(messages))]
            else:
                predicted = [(prefixes[i][checksum_offset] - prefixes[i][start]) % 256 for i in range(len(messages))]
            
            if all(predicted[i] == messages[i][checksum_offset] for i in range(len(messages))):
                # could return something falsely 'included like a protocol byte that is set to zero
                # ^^ this is why it's important to have comprehensive messaging before we 
                return {
                    "algorithm": algo_name,
                    "covers_offsets": (start, checksum_offset-1),
                    "checksum_offset": checksum_offset, # for now this is a static assumption
                    "end_offset": end_offset,
                }
    return None

def extract_data_bytes(messages: list[bytes], data_range: tuple[int, int]) -> list[bytes]:
    """ isolate the data based on a provided data_range parameter """ 
    start, end = data_range
    return [m[start:end + 1] for m in messages]

COMMON_SCALES = [1, 10, 100, 1000, 0.1, 0.01, 0.001]
COMMON_PRECISIONS = [255, 1023, 4095, 65535]  # 8/10/12/16-bit full-scale counts

# NOTE: O(spans * orders * scales * messages) — re-decodes every span from scratch.
# Same overlapping-subproblem shape as find_checksum_range's prefix trick; fix with
# a similar prefix-based approach later instead of re-slicing per (start, end).
def find_scaled_value(
        messages: list[bytes],
        expected_values: list[float],
        tolerance: int = 0, scales: list[float] | None = None,
        span: tuple[int,int] | None = None,
        min_value: float = 0,
        max_value: float | None = None,
        byte_order: str | None = None,
        ) -> dict:
    length = len(messages[0])
    scale_candidates = [(s, None) for s in (scales if scales is not None else COMMON_SCALES)]
    if max_value is not None and max_value != min_value:
        # a precision (resolution/full-scale count) is only a usable scale once
        # we know the physical range it's spread across: scale = precision / range
        scale_candidates += [(p / (max_value - min_value), p) for p in COMMON_PRECISIONS]
    if span is not None:
        region_start, region_end = span
        spans = [(s, e) for s in range(region_start, region_end + 1) for e in range(s, region_end + 1)]
    else:
        spans = [(s, e) for s in range(length) for e in range(s, length)]
    orders = (byte_order,) if byte_order is not None else ("big", "little")
    distinct_expected = len(set(expected_values))

    matches = []
    closest_miss = None
    closest_deviation = None
    for start, end in spans:
        for order in orders:
            raws = [int.from_bytes(m[start:end + 1], order) for m in messages]
            for scale, precision in scale_candidates:
                targets = [round(v*scale) for v in expected_values]
                if any(v != 0 and t == 0 for v, t in zip(expected_values, targets)):
                    continue
                if len(set(targets)) < distinct_expected:
                    continue
                # deviation in real units (not raw counts), so candidates at
                # different scales are comparable on equal footing
                deviations = [abs(raws[i] - targets[i]) / scale for i in range(len(messages))]
                max_deviation = max(deviations)
                if max_deviation <= tolerance:
                    matches.append({
                        "start": start,
                        "end": end,
                        "byte_order": order,
                        "scale": scale,
                        "precision": precision,
                        "decoded_values": [raws[i] / scale for i in range(len(messages))],
                    })
                if closest_deviation is None or max_deviation < closest_deviation:
                    closest_deviation = max_deviation
                    closest_miss = {
                        "start": start,
                        "end": end,
                        "byte_order": order,
                        "scale": scale,
                        "precision": precision,
                        "decoded_values": [raws[i] / scale for i in range(len(messages))],
                        "deviation": max_deviation,
                    }
    return {"matches": matches, "closest_miss": None if matches else closest_miss}


if __name__ == "__main__": 
    if sys.argv[1] == "capture":
        log_capture_to_file("usbmon3", 2, "capture_log.jsonl")
    elif sys.argv[1] == "analyze": 
        records = list(load_capture_log("capture_log.jsonl"))
        out_messages = [data for seq, ts, direction, data in records if direction == "OUT"]
        for entry in analyze_byte_variability(out_messages):
            print(entry)
        print(find_checksum_range(out_messages))