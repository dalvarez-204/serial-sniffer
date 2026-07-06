import subprocess
import json
import sys

def stream_usb_capture(interface: str, device_address: int): 
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
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1) # PIPE captures tshark's output
    # text=True decodes output as text automatically, is this what we really want?
    for line in proc.stdout: 
        timestamp_str, endpoint_str, capdata_str = line.strip().split(",")

        timestamp = float(timestamp_str)
        direction = "IN" if int(endpoint_str, 16) & 0x80 else "OUT"
        data = bytes.fromhex(capdata_str.replace(":", ""))
        yield timestamp, direction, data

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

def load_capture_log(filepath:str):
    with open(filepath) as f:
        for line in f:
            record = json.loads(line)
            yield record["timestamp"], record["direction"], bytes.fromhex(record["data_hex"])

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
        })
    return results

if __name__ == "__main__": 
    if sys.argv[1] == "capture":
        log_capture_to_file("usbmon3", 2, "capture_log.jsonl")
    elif sys.argv[1] == "analyze": 
        records = list(load_capture_log("capture_log.jsonl"))
        out_messages = [data for ts, direction, data in records if direction == "OUT"]
        for entry in analyze_byte_variability(out_messages):
            print(entry)