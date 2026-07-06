import subprocess

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


if __name__ == "__main__": 
    for ts, direction, data in stream_usb_capture("usbmon3", 2):
        print(ts,direction, data)