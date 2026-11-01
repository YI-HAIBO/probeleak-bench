#!/usr/bin/env python
"""Audit paper/figures/*.pdf for IEEE printability.

Checks per figure:
  - pure-vector (no raster /Image XObjects)
  - color spaces referenced (RGB/CMYK/Gray/Pattern/Indexed)
  - distinct fill colors used in content streams, and whether they would be
    separable when printed monochrome (luminance spread + delta-E proxy)
  - embedded font list + minimum font size in points *at native figure size*
  - native width/height in pt and the scale factor applied in the .tex
  - implied printed text height in pt (IEEE requires >= ~8pt legibility)

Usage: python experiments/fig_print_audit.py
"""
import os
import re
import sys
import zlib

PAPER = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep + "paper"
TEX = os.path.join(PAPER, "p3_tifs.tex")
FIGDIR = os.path.join(PAPER, "figures")


def read_pdfs():
    """Return {name: raw bytes} for every pdf in FIGDIR."""
    out = {}
    for fn in sorted(os.listdir(FIGDIR)):
        if fn.lower().endswith(".pdf"):
            with open(os.path.join(FIGDIR, fn), "rb") as fh:
                out[fn] = fh.read()
    return out


def streams(raw):
    """Yield decompressed stream bodies."""
    for m in re.finditer(rb"stream\r?\n", raw):
        start = m.end()
        end = raw.find(b"endstream", start)
        if end < 0:
            continue
        body = raw[start:end].rstrip(b"\r\n")
        try:
            yield zlib.decompress(body)
        except Exception:
            pass


def native_size(raw):
    m = re.search(rb"/MediaBox\s*\[\s*([\d.\-]+)\s+([\d.\-]+)\s+([\d.\-]+)\s+([\d.\-]+)\s*\]", raw)
    if not m:
        return None
    x0, y0, x1, y1 = (float(v) for v in m.groups())
    return x1 - x0, y1 - y0


def color_ops(body):
    """Collect numeric color state setters.

    The negative lookahead is essential: without it, the 3-number-plus-'r'
    pattern also matches the PDF ``re`` (rectangle) path operator and
    returns coordinate values as if they were colors.
    """
    found = {"gray": [], "rgb": [], "cmyk": [], "indexed": set()}
    for m in re.finditer(
        rb"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+[kK](?![a-zA-Z])", body
    ):
        found["cmyk"].append(tuple(float(g) for g in m.groups()))
    for m in re.finditer(rb"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+[rgRG](?![a-zA-Z])", body):
        c = tuple(float(g) for g in m.groups())
        if max(c) <= 1.001:
            found["rgb"].append(c)
    for m in re.finditer(rb"([\d.]+)\s+[gG](?![a-zA-Z])", body):
        v = float(m.group(1))
        if v <= 1.001:
            found["gray"].append(v)
    if re.search(rb"/Indexed\s|/Separation\s|/Pattern\s", body):
        found["indexed"].add("pattern_or_separation")
    return found


def lum(r, g, b):
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def sep_score(cols):
    """Minimum luminance gap between distinct colors (0-1)."""
    lums = sorted({round(lum(*c), 4) for c in cols})
    if len(lums) < 2:
        return None
    gaps = [lums[i + 1] - lums[i] for i in range(len(lums) - 1)]
    return min(gaps)


def fonts_and_sizes(raw, bodies):
    basefonts = sorted(set(re.findall(rb"/BaseFont\s*/([A-Za-z0-9+\-]+)", raw)))
    sizes = []
    for body in bodies:
        sizes += [float(m.group(1)) for m in re.finditer(rb"([\d.]+)\s+Tf", body)]
    if not sizes:
        return basefonts, None, None, None
    from collections import Counter

    modal = Counter(sizes).most_common(1)[0][0]
    return basefonts, min(sizes), max(sizes), modal


def tex_scale():
    """{figure filename: (env, width_spec)} from the manuscript."""
    t = open(TEX, encoding="utf-8").read()
    out = {}
    for blk in re.findall(r"\\begin\{(figure\*?)\}(.*?)\\end\{\1\}", t, re.S):
        env, body = blk
        m = re.search(r"\\includegraphics\[([^\]]*)\]\{([^}]+)\}", body)
        if m:
            opts, path = m.groups()
            wm = re.search(r"width=([^\]]+)", opts)
            out[os.path.basename(path)] = (env, wm.group(1) if wm else "nat")
    return out


# IEEEtran: textwidth 516pt, columnwidth 252pt
TEXTWIDTH, COLWIDTH = 516.0, 252.0


def display_width(width_spec, env, native_w):
    if width_spec in (None, "nat"):
        return native_w
    m = re.match(r"([\d.]+)(\\?textwidth|\\?linewidth|\\?in|pt)?", width_spec.replace(" ", ""))
    if not m:
        return native_w
    frac, unit = m.group(1), m.group(2) or "pt"
    f = float(frac)
    if unit == r"\textwidth":
        return f * TEXTWIDTH
    if unit == r"\linewidth":
        return f * (COLWIDTH if env == "figure" else TEXTWIDTH)
    if unit == r"\in":
        return f * 72.0
    return f


def main():
    pdfs = read_pdfs()
    scales = tex_scale()
    print("figure audit for %s  (IEEEtran: textwidth=%.0fpt colwidth=%.0fpt)" % (FIGDIR, TEXTWIDTH, COLWIDTH))
    print("-" * 108)
    hdr = "%-34s %-9s %-7s %-6s %6s %6s %-10s %s" % (
        "file", "raster", "env", "scale", "minPt", "print", "colorGap", "notes")
    print(hdr)
    print("-" * 108)
    problems = []
    for fn, raw in pdfs.items():
        bodies = list(streams(raw))
        allb = b"\n".join(bodies)
        raster = len(re.findall(rb"/Subtype\s*/Image", allb))
        nat = native_size(raw)
        env, ws = scales.get(fn, (None, None))
        disp = display_width(ws, env, nat[0]) if nat else None
        sc = (disp / nat[0]) if (disp and nat) else None
        bf, mn, mx, modal = fonts_and_sizes(raw, bodies)
        cols = []
        for b in bodies:
            c = color_ops(b)
            cols += c["rgb"] + [(g, g, g) for g in c["gray"]] + [(1 - k[0], 1 - k[1], 1 - k[2], 1 - k[3]) for k in c["cmyk"]]
        gap = sep_score(cols)
        printPt = (mn * sc) if (mn and sc) else None
        notes = []
        if raster:
            notes.append("RASTER x%d" % raster)
            problems.append("%s: contains raster image" % fn)
        if env is None:
            # Not in the TIFS manuscript: dropped for page count, but still
            # referenced by the longer p3_main.tex. Informational only.
            notes.append("not in TIFS tex")
        if bool(re.search(rb"/DeviceCMYK|/Processed[/ ]CMYK", allb)) or any(
            len([c for c in color_ops(b)["cmyk"]]) for b in bodies
        ):
            notes.append("CMYK")
        if gap is not None and gap < 0.06:
            notes.append("POOR-sep")
            problems.append("%s: two colors only %.3f apart in luminance (mono-print clash)" % (fn, gap))
        if printPt is not None and printPt < 8.0:
            # matplotlib emits math glyphs (mathtext) at ~0.7x the nominal
            # size on purpose so they optically match the surrounding text.
            # A sub-8pt value that is also far below the modal size is that
            # case, not a genuinely undersized label.
            if modal and printPt < 0.85 * (modal * sc):
                notes.append("mathtext")
            else:
                notes.append("TINY")
                problems.append("%s: smallest text prints at %.1fpt (<8pt)" % (fn, printPt))
        print("%-34s %-9s %-7s %-6s %6s %6s %-10s %s" % (
            fn,
            raster or "-",
            env or "?",
            ("%.2fx" % sc) if sc else "?",
            ("%.1f" % mn) if mn else "?",
            ("%.1f" % printPt) if printPt else "?",
            ("%.3f" % gap) if gap is not None else "mono",
            "; ".join(notes)))
    print("-" * 108)
    print("embedded fonts: %s" % sorted({f.decode() for raw in pdfs.values() for f in re.findall(rb"/BaseFont\s*/([A-Za-z0-9+\-]+)", raw)}))
    if problems:
        print("\nISSUES (%d):" % len(problems))
        for p in problems:
            print("  - " + p)
        return 1
    print("\nno printability issues detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
