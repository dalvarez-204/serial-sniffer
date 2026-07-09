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


def build_codegen_context(label, direction, deciphered, capture_records, analysis):
    """Gathers everything needed to describe one labeled message type: framing,
    checksum, the deciphered field, and a few real sample messages."""
    key = f"{label}::{direction}"
    matching = [data for _, d, data in capture_records if d == direction]
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
        "deciphered_field": deciphered.get(key),
    }


def build_prompt(context):
    return f"""You are generating a small, self-contained Python function pair for talking \
to a serial instrument, based entirely on ground truth inferred from captured traffic. Do \
not invent fields, offsets, or behavior beyond what's given below.

Context (JSON):
{json.dumps(context, indent=2)}

Write:
1. `encode_{context["label"]}(value: float) -> bytes` — builds a full outgoing frame with \
`value` written into the deciphered byte range using the given byte order and scale, and \
every other byte held at whatever constant value appears across the sample messages \
(recompute the checksum from the "checksum" info if one was found; don't hardcode it).
2. `decode_{context["label"]}(data: bytes) -> float` — extracts the same field from an \
incoming message of this shape.

Only fully implement the direction that's actually given ("{context["direction"]}"); write \
the other function as the natural inverse using the same sample bytes as the constant \
template. Include type hints and one short docstring per function. Output ONLY the Python \
code, no prose, no markdown fences.
"""


def _mock_response(context):
    label = context["label"]
    return (
        "# MOCK OUTPUT — no ANTHROPIC_API_KEY set on the server.\n"
        "# Export one and retry to get a real generated function from Claude.\n"
        f"# Context that would have been sent:\n# {json.dumps(context)}\n\n"
        f"def encode_{label}(value: float) -> bytes:\n"
        f'    raise NotImplementedError("stub — set ANTHROPIC_API_KEY to generate this for real")\n\n\n'
        f"def decode_{label}(data: bytes) -> float:\n"
        f'    raise NotImplementedError("stub — set ANTHROPIC_API_KEY to generate this for real")\n'
    )


def generate_driver_code(context):
    """Returns (code, is_mock)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _mock_response(context), True

    import anthropic  # only required once a key is actually set

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=2048,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": build_prompt(context)}],
    )
    code = "".join(block.text for block in response.content if block.type == "text")
    return code, False
