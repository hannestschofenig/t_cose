import sys
import os
import cbor2
import binascii
import re

LABEL_NAMES = {}
ALG_NAMES = {}
HEADER_LABELS = {
    1: "alg",
    4: "kid",
}


def load_maps_from_cddl(path):
    alg_re = re.compile(r";\s*([-+]?\d+)\s*;\s*(.+)")
    label_re = re.compile(r";\s*label\s+([-+]?\d+)\s+(\S+)", re.IGNORECASE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                m_alg = alg_re.search(line)
                if m_alg:
                    ALG_NAMES[int(m_alg.group(1))] = m_alg.group(2).strip()
                m_lab = label_re.search(line)
                if m_lab:
                    LABEL_NAMES[int(m_lab.group(1))] = m_lab.group(2).strip()
    except OSError:
        pass


def format_bytes(bstr, indent):
    hexs = binascii.hexlify(bstr).decode()
    max_len = 72 - len(indent) - 3  # h' + ' plus indent
    chunks = [hexs[i:i + max_len] for i in range(0, len(hexs), max_len)]
    if len(chunks) == 1:
        return "h'" + chunks[0] + "'"
    lines = []
    lines.append(indent + "h'" + chunks[0])
    for c in chunks[1:]:
        lines.append(indent + "  " + c)
    lines[-1] = lines[-1] + "'"
    return "\n".join(lines)


def diag(obj, level=0, label_map=None):
    indent = "  " * level
    def indent_multiline(text, pad):
        if "\n" not in text:
            return text
        lines = text.split("\n")
        return ("\n" + pad).join(lines)
    if isinstance(obj, bytes):
        return format_bytes(obj, indent)
    if isinstance(obj, list):
        inner = []
        for x in obj:
            elem = diag(x, level + 1, label_map)
            elem = indent_multiline(elem, indent + "  ")
            inner.append(indent + "  " + elem + ",")
        return "[\n" + "\n".join(inner) + "\n" + indent + "]"
    if isinstance(obj, dict):
        lines = []
        items = list(obj.items())
        active_labels = label_map if label_map else (LABEL_NAMES if all(isinstance(k, int) for k, _ in items) else {})
        for idx, (k, v) in enumerate(items):
            comma = "," if idx < len(items) - 1 else ""
            k_txt = diag(k, level + 1, label_map)
            if isinstance(k, int) and active_labels and k in active_labels:
                k_txt = f"/ {active_labels[k]} / {k_txt}"
            next_map = label_map
            if k == "protected":
                next_map = HEADER_LABELS
            v_txt = diag(v, level + 1, next_map)
            if k == 3 and isinstance(v, int) and v in ALG_NAMES:
                v_txt = f"{v_txt} / {ALG_NAMES[v]} /"
            v_txt = indent_multiline(v_txt, indent + "    ")
            lines.append(f"{indent}  {k_txt}: {v_txt}{comma}")
        inner = "\n".join(lines)
        return "{\n" + inner + "\n" + indent + "}"
    if isinstance(obj, str):
        return '"' + obj + '"'
    return str(obj)


def wrap_diag(text, width=72):
    lines = []
    for raw_line in text.splitlines():
        parts = raw_line.split(" ")
        current = ""
        for part in parts:
            if current and len(current) + 1 + len(part) > width:
                lines.append(current)
                current = part
            else:
                current = part if not current else current + " " + part
        if current:
            lines.append(current)
    return "\n".join(lines)


if len(sys.argv) >= 3:
    load_maps_from_cddl(sys.argv[2])
else:
    default_cddl = os.path.join(os.path.dirname(__file__), "cose_pqc.cddl")
    load_maps_from_cddl(default_cddl)

with open(sys.argv[1], "rb") as f:
    data = cbor2.load(f)

# Unwrap COSE_Sign1 (tag 18) into a dict for nicer display
if isinstance(data, cbor2.CBORTag) and getattr(data, "tag", None) == 18:
    data = data.value

# Special-case COSE_Sign1: [protected bstr, unprotected map, payload bstr/nil, signature bstr]
if isinstance(data, list) and len(data) == 4:
    prot = data[0]
    unprot = data[1]
    payload = data[2]
    sig = data[3]
    try:
        prot_decoded = cbor2.loads(prot) if isinstance(prot, (bytes, bytearray)) else prot
    except Exception:
        prot_decoded = prot
    data = {
        "protected": prot_decoded,
        "unprotected": unprot,
        "payload": payload,
        "signature": sig,
    }

# Use header label map for protected header when present
print(wrap_diag(diag(data)))
