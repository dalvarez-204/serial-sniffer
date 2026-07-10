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


def build_codegen_context(label, direction, deciphered_fields, capture_records, analysis):
    """Gathers everything needed to describe one labeled message type: framing,
    checksum, every deciphered parameter for this label+direction (there can be
    several — e.g. a "set_waveform" command's wave_type/freq/amplitude/offset
    all live in one frame), and a few real sample messages."""
    matching = [data for _, _, d, data in capture_records if d == direction]
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


def _call_claude(client, context, correction=None):
    response = client.messages.create(
        model=CLAUDE_MODEL,
        # generous headroom: adaptive thinking's tokens count against this same
        # budget, and a multi-parameter message can burn well past 2048 of
        # thinking alone before it ever gets to writing code — a too-small
        # cap here silently returns empty output (stop_reason "max_tokens")
        max_tokens=8192,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": build_prompt(context, correction)}],
    )
    code = "".join(block.text for block in response.content if block.type == "text")
    return code, response.stop_reason


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
