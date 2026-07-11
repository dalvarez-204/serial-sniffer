"""Turns a deciphered label into a small, self-contained Python encode/decode
function pair, grounded in the actual captured bytes and analysis — not
invented. If ANTHROPIC_API_KEY isn't set, returns a clearly-marked stub so the
rest of the pipeline (context building, prompt, endpoint, UI) can be
exercised and tested before a key is available.
"""

import json
import os

CLAUDE_MODEL = "claude-opus-4-8"
SAMPLE_LIMIT = 5


def build_codegen_context(label, direction, deciphered_fields, capture_records, analysis, labels):
    """Gathers everything needed to describe one labeled message type: framing,
    checksum, every deciphered parameter for this label+direction (there can be
    several — e.g. a "set_waveform" command's wave_type/freq/amplitude/offset
    all live in one frame), and a few real sample messages.

    "labels" (from labels.json, keyed by message seq/index) is required to
    pick out messages that actually carry THIS label — filtering by
    direction alone silently mixes in other same-direction, same-length
    commands (e.g. set_ocp's samples leaking into set_voltage's context),
    which then get copied in as "constant" bytes for the wrong command."""
    matching = [
        data for seq, _, d, data in capture_records
        if d == direction and labels.get(str(seq), {}).get("name") == label
    ]
    if not matching:
        return None

    length = len(matching[0])
    group_key = f"{direction}_{length}"
    group_analysis = analysis.get(group_key, {})

    return {
        "label": label,
        "direction": direction,
        "length": length,
        "sample_hex": [m.hex() for m in matching[:SAMPLE_LIMIT]],
        "byte_variability": group_analysis.get("variability"),
        "checksum": group_analysis.get("checksum"),
        "deciphered_fields": deciphered_fields,
    }


def build_prompt(context, correction=None):
    param_names = [f["param"] for f in context["deciphered_fields"]]
    example_field = context["deciphered_fields"][0]
    example_raw = round(1.0 * example_field["scale"])
    correction_note = (
        f"\n\nA previous attempt at this got the scale direction backwards: {correction}\n"
        "Fix that specific mistake in this attempt.\n"
        if correction
        else ""
    )
    return f"""You are generating a small, self-contained Python function pair for talking \
to a serial instrument, based entirely on ground truth inferred from captured traffic. Do \
not invent fields, offsets, or behavior beyond what's given below.

Context (JSON):
{json.dumps(context, indent=2)}

"deciphered_fields" lists every named parameter this message carries — a real command often
sets several fields at once (e.g. wave_type, freq, amplitude, offset all in one frame), so
the generated function must accept and pack ALL of them, not just one.

IMPORTANT — scale direction: "scale" is raw-counts-per-unit. To go from a real-world value to
the raw integer written into the bytes, you MULTIPLY: `raw = round(value * scale)`. To go the
other way (decoding), you DIVIDE: `value = raw / scale`. Worked example using this context's
own "{example_field["param"]}" field (scale {example_field["scale"]}): a real value of 1.0
encodes to raw {example_raw}, and decoding raw {example_raw} back gives approximately 1.0.
Do not invert this.{correction_note}

{_task_instructions(context, param_names)}

Include type hints and one short docstring. Output ONLY the Python code, no prose, no \
markdown fences.
"""


def _task_instructions(context, param_names):
    label = context["label"]
    if context["direction"] == "OUT":
        return f"""Write `encode_{label}({", ".join(f"{p}: float" for p in param_names)}) -> bytes` — \
builds a full outgoing frame with each named parameter written into its own deciphered byte \
range using its given byte order and scale. Every byte NOT covered by a deciphered field must \
be copied verbatim from the first sample message above — regardless of whether \
"byte_variability" calls it constant or varying, since it hasn't been deciphered there is no \
ground truth for what it should be, so hold it fixed rather than guessing (the one exception: \
recompute the checksum from the "checksum" info if one was found — don't hardcode it).

This is an outgoing (OUT) message — CLOAK only ever sends this shape, never receives it, so \
do NOT write a decode function, only encode_{label}."""
    return f"""Write `decode_{label}(data: bytes) -> dict` — extracts every deciphered \
parameter from an incoming message of this shape and returns them as a dict keyed by \
parameter name.

This is an incoming (IN) message — CLOAK only ever receives this shape, never constructs it, \
so do NOT write an encode function, only decode_{label}."""


def _mock_response(context):
    label = context["label"]
    direction = context["direction"]
    param_names = [f["param"] for f in context["deciphered_fields"]] or ["value"]
    args = ", ".join(f"{p}: float" for p in param_names)
    header = (
        "# MOCK OUTPUT — no ANTHROPIC_API_KEY set on the server.\n"
        "# Export one and retry to get a real generated function from Claude.\n"
        f"# Context that would have been sent:\n# {json.dumps(context)}\n\n"
    )
    if direction == "OUT":
        return header + (
            f"def encode_{label}({args}) -> bytes:\n"
            f'    raise NotImplementedError("stub — set ANTHROPIC_API_KEY to generate this for real")\n'
        )
    return header + (
        f"def decode_{label}(data: bytes) -> dict:\n"
        f'    raise NotImplementedError("stub — set ANTHROPIC_API_KEY to generate this for real")\n'
    )


def reference_decode(sample_hex, deciphered_fields):
    """Ground-truth decode using the exact same math as the rest of this
    codebase (find_scaled_value etc), independent of anything an LLM wrote —
    used to sanity-check the generated decode_<label>() function."""
    data = bytes.fromhex(sample_hex)
    return {
        f["param"]: int.from_bytes(data[f["start"]:f["end"] + 1], f["byte_order"]) / f["scale"]
        for f in deciphered_fields
    }


def verify_generated_code(code, context):
    """Runs the generated function against a real sample and checks its
    arithmetic against reference_decode() (ground truth, independent of
    anything an LLM wrote). Returns an error string describing the mismatch,
    or None if it checks out. Only the direction-appropriate function is
    generated/checked — IN messages only ever get decode_<label>, OUT
    messages only ever get encode_<label>."""
    if not context["sample_hex"]:
        return None

    label = context["label"]
    direction = context["direction"]
    namespace = {}
    try:
        exec(code, namespace)  # noqa: S102 — trusted pipeline output, not user input
    except Exception as e:
        return f"generated code failed to execute: {e}"

    sample_hex = context["sample_hex"][0]
    # Tolerance is tied to each field's own quantization granularity (1/scale
    # = real-world units per raw count), not a generic floor — a fixed floor
    # like 0.5 would swallow a multiply/divide inversion whole for any field
    # whose real values happen to sit under that floor (e.g. a 0-3.3V signal).
    field_by_param = {f["param"]: f for f in context["deciphered_fields"]}
    expected = reference_decode(sample_hex, context["deciphered_fields"])

    if direction == "IN":
        decode_fn = namespace.get(f"decode_{label}")
        if decode_fn is None:
            return f"no decode_{label}() function found in the generated code"
        try:
            actual = decode_fn(bytes.fromhex(sample_hex))
        except Exception as e:
            return f"decode_{label}() raised {e}"
        if not isinstance(actual, dict):
            return f"decode_{label}() returned {type(actual).__name__}, expected a dict"
        for param, expected_value in expected.items():
            actual_value = actual.get(param)
            tolerance = max(1 / field_by_param[param]["scale"], 0.01)
            if actual_value is None or abs(actual_value - expected_value) > tolerance:
                return (
                    f'decode_{label}()["{param}"] returned {actual_value} for a real captured '
                    f"sample, but the ground truth (same start/end/byte_order/scale this context "
                    f"was built from) says it should be ~{expected_value:.4f} — likely a scale "
                    f"direction or endianness bug"
                )
        return None

    # direction == "OUT": there's no generated decode_<label>() to round-trip
    # through, so check encode_<label>()'s own output directly, byte range by
    # byte range, against the ground-truth math.
    encode_fn = namespace.get(f"encode_{label}")
    if encode_fn is None:
        return f"no encode_{label}() function found in the generated code"
    try:
        encoded = encode_fn(**expected)
    except Exception as e:
        return f"encode_{label}(**{expected}) raised {e}"
    if not isinstance(encoded, bytes):
        return f"encode_{label}() returned {type(encoded).__name__}, expected bytes"

    for param, expected_value in expected.items():
        f = field_by_param[param]
        raw = int.from_bytes(encoded[f["start"]:f["end"] + 1], f["byte_order"])
        actual_value = raw / f["scale"]
        # allow ~1.5 raw counts of rounding slack from encode's own quantization
        tolerance = max(1.5 / f["scale"], 0.01)
        if abs(actual_value - expected_value) > tolerance:
            return (
                f'encode_{label}(**{expected}) wrote "{param}" as {actual_value} (raw {raw}), '
                f"expected ~{expected_value:.4f} — likely a scale direction bug"
            )
    return None


def _call_claude_raw(client, prompt):
    response = client.messages.create(
        model=CLAUDE_MODEL,
        # generous headroom: adaptive thinking's tokens count against this same
        # budget, and a multi-parameter message can burn well past 2048 of
        # thinking alone before it ever gets to writing code — a too-small
        # cap here silently returns empty output (stop_reason "max_tokens")
        max_tokens=8192,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": prompt}],
    )
    code = "".join(block.text for block in response.content if block.type == "text")
    return code, response.stop_reason


def _call_claude(client, context, correction=None):
    return _call_claude_raw(client, build_prompt(context, correction))


def generate_driver_code(context):
    """Returns (code, is_mock). Verifies the generated decode function against
    a real sample and retries once with a corrective note if it's wrong,
    rather than silently handing back code that decodes incorrectly."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _mock_response(context), True

    import anthropic  # only required once a key is actually set

    client = anthropic.Anthropic(api_key=api_key)

    code, stop_reason = _call_claude(client, context)
    if not code.strip():
        return f"# Claude returned no code (stop_reason: {stop_reason}) — try again.", True

    error = verify_generated_code(code, context)
    if error:
        code, stop_reason = _call_claude(client, context, correction=error)
        if not code.strip():
            return f"# Claude returned no code on retry (stop_reason: {stop_reason}) — try again.", True
        retry_error = verify_generated_code(code, context)
        if retry_error:
            code = (
                f"# WARNING: this code failed self-verification twice — check the arithmetic\n"
                f"# by hand before trusting it. Latest issue: {retry_error}\n\n{code}"
            )

    return code, False


def _find_discriminators(label_contexts):
    """For every length shared by more than one deciphered IN-direction
    label — e.g. two different incoming reading shapes that happen to be
    the same size — finds a byte offset that's constant within each label's
    OWN samples but takes a different constant value between labels. That's
    the real "command type" byte poll()'s dispatcher needs when length alone
    can't tell two incoming message shapes apart. OUT-direction labels are
    excluded entirely: poll() never has to decide between them, since
    CLOAK never decodes its own outgoing traffic, only what it sends by
    calling send_<label>() directly. Returns {(direction, length):
    {"offset": int, "values": {label: value}}}; a group left out of the
    result had no such offset, so poll() falls back to matching by length
    alone for it."""
    groups = {}
    for ctx in label_contexts:
        if ctx["direction"] != "IN":
            continue
        groups.setdefault((ctx["direction"], ctx["length"]), []).append(ctx)

    discriminators = {}
    for key, group in groups.items():
        if len(group) < 2:
            continue
        _, length = key
        per_label_constant = {}
        for ctx in group:
            samples = [bytes.fromhex(h) for h in ctx["sample_hex"]]
            constants = []
            for offset in range(length):
                values_at_offset = {s[offset] for s in samples}
                constants.append(next(iter(values_at_offset)) if len(values_at_offset) == 1 else None)
            per_label_constant[ctx["label"]] = constants

        for offset in range(length):
            per_label_value = {label: consts[offset] for label, consts in per_label_constant.items()}
            if any(v is None for v in per_label_value.values()):
                continue
            if len(set(per_label_value.values())) == len(per_label_value):  # every label has a distinct value here
                discriminators[key] = {"offset": offset, "values": per_label_value}
                break
    return discriminators


def build_frame_sync_prompt(in_samples, correction=None):
    correction_note = (
        f"\n\nA previous attempt at this failed: {correction}\nFix that specific mistake in this attempt.\n"
        if correction
        else ""
    )
    return f"""You are writing a byte-stream frame synchronizer for a serial instrument protocol, \
based entirely on the real captured messages below — do not invent structure that isn't \
evidenced by every sample.

Real captured incoming messages (hex, one per line, in the order they were captured — there \
may be more than one message shape mixed in):
{chr(10).join(in_samples)}

Write ONLY this function:

def read_frame(buf: bytes) -> tuple[bytes | None, bytes]:
    \"\"\"Given an accumulating byte buffer from a live serial read, finds and returns the \
first complete message in it (start marker, length field, checksum, end marker — whatever \
the samples above actually show), and whatever bytes are left in buf after that message. \
Returns (None, buf) unchanged if buf doesn't yet contain one full message.\"\"\"

Infer any start/end markers, length fields, and checksums directly from the samples above — \
don't assume a specific scheme that isn't actually evidenced.{correction_note}

Output ONLY the Python function code, no prose, no markdown fences, no other functions."""


def verify_frame_sync(code, in_samples):
    """Concatenates the real sample messages into one continuous buffer (as
    they'd appear back-to-back on a live wire) and checks read_frame()
    recovers exactly those messages, in order, byte-for-byte — ground truth
    here is just the samples themselves, nothing an LLM wrote is trusted."""
    namespace = {}
    try:
        exec(code, namespace)  # noqa: S102 — trusted pipeline output, not user input
    except Exception as e:
        return f"generated code failed to execute: {e}"

    read_frame = namespace.get("read_frame")
    if read_frame is None:
        return "no read_frame() function found in the generated code"

    expected = [bytes.fromhex(h) for h in in_samples]
    buf = b"".join(expected)
    recovered = []
    for _ in range(len(expected) + 2):  # a couple extra calls to catch over/under-reads
        try:
            frame, buf = read_frame(buf)
        except Exception as e:
            return f"read_frame() raised {e}"
        if frame is None:
            break
        recovered.append(frame)

    if recovered != expected:
        return (
            f"expected read_frame() to recover {len(expected)} messages matching the real "
            f"samples exactly, in order, but got {len(recovered)}: {[f.hex() for f in recovered]}"
        )
    return None


def generate_frame_sync_code(client, in_samples):
    """Returns (code, error). Mirrors generate_driver_code's retry-once
    pattern: self-verify against the real concatenated samples, retry once
    with the concrete mismatch if it's wrong."""
    code, stop_reason = _call_claude_raw(client, build_frame_sync_prompt(in_samples))
    if not code.strip():
        return f"# Claude returned no code (stop_reason: {stop_reason})", "no code returned"

    error = verify_frame_sync(code, in_samples)
    if error:
        code, stop_reason = _call_claude_raw(client, build_frame_sync_prompt(in_samples, correction=error))
        if not code.strip():
            return f"# Claude returned no code on retry (stop_reason: {stop_reason})", "no code returned on retry"
        error = verify_frame_sync(code, in_samples)
    return code, error


def assemble_full_driver(label_results, discriminators, frame_sync_code):
    """Deterministically stitches the already-generated, already-verified
    per-label encode_/decode_ functions plus the frame synchronizer into one
    class. The wiring itself (which decode_ goes with which frame shape,
    which method calls which encode_) is mechanical given what's already
    known, so it's plain Python here rather than left for an LLM to
    reinvent — the only two things Claude actually wrote are the per-label
    byte math and the frame synchronizer, both already self-verified."""
    parts = [frame_sync_code.strip()] if frame_sync_code else []
    parts += [r["code"].strip() for r in label_results]
    functions_src = "\n\n\n".join(parts)

    send_methods = []
    for r in label_results:
        if r["direction"] != "OUT":
            continue
        args = ", ".join(f"{p}: float" for p in r["params"])
        call_args = ", ".join(f"{p}={p}" for p in r["params"])
        send_methods.append(
            f'    def send_{r["label"]}(self, {args}) -> None:\n'
            f'        self.ser.write(encode_{r["label"]}({call_args}))'
        )
    send_src = "\n\n".join(send_methods)

    discriminated_labels = {label for info in discriminators.values() for label in info["values"]}
    dispatch_lines = []
    for (direction, length), info in discriminators.items():
        for label, value in info["values"].items():
            dispatch_lines.append(
                f"        if len(frame) == {length} and frame[{info['offset']}] == {value}:\n"
                f'            return "{label}", decode_{label}(frame)'
            )
    for r in label_results:
        if r["direction"] != "IN" or r["label"] in discriminated_labels:
            continue
        dispatch_lines.append(
            f'        if len(frame) == {r["length"]}:\n'
            f'            return "{r["label"]}", decode_{r["label"]}(frame)'
        )
    dispatch_src = "\n".join(dispatch_lines) if dispatch_lines else "        pass"

    if frame_sync_code:
        poll_method = '''    def poll(self) -> dict | None:
        """Reads whatever's available, extracts and decodes at most one
        complete message, publishes its fields to Nominal if a dataset was
        attached, and appends it to the local log file if one was attached.
        Returns {"label": ..., "values": {...}}, or None if no full message
        is buffered yet."""
        self._buf += self.ser.read(4096)
        frame, self._buf = read_frame(self._buf)
        if frame is None:
            return None
        label, values = self._dispatch(frame)
        if label is None:
            return None
        if self._stream is not None or self._log_file is not None:
            import datetime
            now = datetime.datetime.now()
            if self._stream is not None:
                for param, value in values.items():
                    self._stream.enqueue(channel_name=f"{label}.{param}", timestamp=now, value=value)
            if self._log_file is not None:
                import json
                self._log_file.write(json.dumps({"label": label, "timestamp": now.isoformat(), "values": values}) + "\\n")
                self._log_file.flush()
        return {"label": label, "values": values}'''
    else:
        poll_method = '''    def poll(self) -> dict | None:
        """No IN-direction fields were deciphered yet, so there's nothing to read/decode."""
        raise NotImplementedError("no IN-direction deciphered fields — nothing to poll")'''

    class_src = f'''class InstrumentDriver:
    """Generated by CLOAK from real captured traffic. poll() reads and
    decodes incoming messages; send_<label>() encodes and writes outgoing
    commands; every decoded parameter is published to Nominal Core as its
    own channel ("<label>.<param>") if a dataset RID is given, and/or
    appended as a JSON line to a local log file if a path is given — the
    two are independent, use either, both, or neither."""

    def __init__(
        self,
        port: str,
        baud: int = 115200,
        nominal_dataset_rid: str | None = None,
        nominal_profile: str = "default",
        local_log_path: str | None = None,
    ):
        import serial
        self.ser = serial.Serial(port, baud, timeout=0.2)
        self._buf = b""
        self._stream = None
        if nominal_dataset_rid:
            from nominal.core import NominalClient
            client = NominalClient.from_profile(nominal_profile)
            dataset = client.get_dataset(nominal_dataset_rid)
            self._stream = dataset.get_write_stream()
        self._log_file = open(local_log_path, "a") if local_log_path else None

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
        if self._log_file is not None:
            self._log_file.close()
        self.ser.close()

{send_src if send_src else "    pass"}

    def _dispatch(self, frame: bytes):
{dispatch_src}
        return None, None

{poll_method}
'''

    return f"{functions_src}\n\n\n{class_src}"


def generate_full_driver_code(capture_records, analysis, all_deciphered, labels):
    """Returns (code, warnings, is_mock). Spans every deciphered label —
    unlike generate_driver_code, which only ever handles one label+direction
    at a time. Each label's encode_/decode_ is generated and self-verified
    exactly as it already is today; the frame synchronizer is generated and
    self-verified against the real concatenated IN samples; the class
    wiring around them is deterministic, not LLM output."""
    by_label_direction = {}
    for entry in all_deciphered.values():
        by_label_direction.setdefault((entry["label"], entry["direction"]), []).append(entry)

    if not by_label_direction:
        return None, ["no deciphered fields yet — mark at least one field deciphered first"], True

    label_contexts = []
    for (label, direction), fields in by_label_direction.items():
        ctx = build_codegen_context(label, direction, fields, capture_records, analysis, labels)
        if ctx is not None:
            label_contexts.append(ctx)

    if not label_contexts:
        return None, ["no captured messages match any deciphered label"], True

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        stub = "\n\n\n".join(_mock_response(ctx) for ctx in label_contexts)
        return stub, ["no ANTHROPIC_API_KEY set on the server — showing stubs only"], True

    import anthropic  # only required once a key is actually set

    client = anthropic.Anthropic(api_key=api_key)

    warnings = []
    label_results = []
    for ctx in label_contexts:
        code, _ = generate_driver_code(ctx)
        if code.lstrip().startswith("# WARNING"):
            warnings.append(f'"{ctx["label"]}" ({ctx["direction"]}): self-verification failed twice — check its arithmetic by hand')
        label_results.append({
            "label": ctx["label"],
            "direction": ctx["direction"],
            "length": ctx["length"],
            "code": code,
            "params": [f["param"] for f in ctx["deciphered_fields"]],
        })

    discriminators = _find_discriminators(label_contexts)
    in_contexts = [ctx for ctx in label_contexts if ctx["direction"] == "IN"]
    ambiguous_lengths = {
        ctx["length"]
        for ctx in in_contexts
        if sum(1 for c in in_contexts if c["length"] == ctx["length"]) > 1
    } - {length for (_, length) in discriminators.keys()}
    if ambiguous_lengths:
        warnings.append(
            f"couldn't find a byte that distinguishes incoming labels sharing length(s) "
            f"{sorted(ambiguous_lengths)} — poll() will match whichever of those comes first"
        )

    in_samples = [h for ctx in label_contexts if ctx["direction"] == "IN" for h in ctx["sample_hex"]]
    frame_sync_code = None
    if in_samples:
        frame_sync_code, frame_sync_error = generate_frame_sync_code(client, in_samples)
        if frame_sync_error:
            warnings.append(f"frame sync (read_frame): self-verification failed — {frame_sync_error}")
    else:
        warnings.append("no IN-direction deciphered labels — poll() has nothing to read; only send_<label> methods were generated")

    code = assemble_full_driver(label_results, discriminators, frame_sync_code)
    return code, warnings, False
