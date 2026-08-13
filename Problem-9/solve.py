#!/usr/bin/env python3
"""Media forensics: LSB image payload, WAV tone->hex, sprite-sheet scene changes."""
import sys, wave, math, struct
from pathlib import Path
from PIL import Image

BASE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent

# ---------- 1. LSB of blue channel ----------
def lsb_string(path):
    im = Image.open(path).convert("RGB")
    w, h = im.size
    px = im.load()
    bits = []
    for y in range(h):
        for x in range(w):
            bits.append(px[x, y][2] & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        b = 0
        for k in range(8):
            b = (b << 1) | bits[i + k]
        if b == 0:
            break
        out.append(b)
    return out.decode("ascii", "replace")

# ---------- 2. WAV tones ----------
FREQS = {i: 400 + 160 * i for i in range(16)}

def goertzel(samples, f, sr):
    k = 2 * math.cos(2 * math.pi * f / sr)
    s1 = s2 = 0.0
    for x in samples:
        s0 = x + k * s1 - s2
        s2, s1 = s1, s0
    return s1 * s1 + s2 * s2 - k * s1 * s2

def hex_digits(path):
    w = wave.open(str(path), "rb")
    sr = w.getframerate()
    n = w.getnframes()
    raw = w.readframes(n)
    data = struct.unpack("<%dh" % n, raw)
    tone = int(0.250 * sr)
    gap = int(0.040 * sr)
    # locate non-silent runs
    runs, i = [], 0
    while i < n:
        if abs(data[i]) > 200:
            j = i
            while j < n and max(abs(v) for v in data[j:min(j + 200, n)]) > 200:
                j += 200
            runs.append((i, min(j, n)))
            i = j
        else:
            i += 1
    if len(runs) != 8:  # fall back to fixed layout
        runs = [(k * (tone + gap), k * (tone + gap) + tone) for k in range(8)]
    out = ""
    for a, b in runs:
        seg = data[a + sr // 200: b - sr // 200]
        best = max(FREQS, key=lambda d: goertzel(seg, FREQS[d], sr))
        out += "%x" % best
    return out

# ---------- 3. Scene changes ----------
def scene_changes(path, cols=6, rows=4):
    im = Image.open(path).convert("RGB")
    W, H = im.size
    fw, fh = W // cols, H // rows
    bases = []
    for r in range(rows):
        for c in range(cols):
            box = im.crop((c * fw, r * fh, (c + 1) * fw, (r + 1) * fh))
            px = list(box.getdata())
            med = tuple(sorted(v[i] for v in px)[len(px) // 2] for i in range(3))
            bases.append(med)
    changes = 0
    for a, b in zip(bases, bases[1:]):
        if max(abs(a[i] - b[i]) for i in range(3)) > 12:
            changes += 1
    return changes, bases

if __name__ == "__main__":
    tok = lsb_string(BASE / "forensics-image.png")
    dig = hex_digits(BASE / "forensics-audio.wav")
    cnt, bases = scene_changes(BASE / "forensics-frames.png")
    print("token :", tok)
    print("digits:", dig)
    print("frames:", bases)
    print("count :", cnt)
    print()
    print(f"{tok}|{dig}|{cnt}")
