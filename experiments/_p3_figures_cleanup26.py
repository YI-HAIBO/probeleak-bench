"""Pass-26: Fix fig1 arrow accuracy — remove wrong D30→scrub arrow,
add missing SQL/tool execution→Consumer arrow."""
import os, sys

BS = chr(92)   # backslash
NL = chr(10)   # newline

SCRIPT = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(SCRIPT)
TARGET = os.path.join(BASE, "experiments", "p3_figures_gen.py")

with open(TARGET, "r", encoding="utf-8") as f:
    src = f.read()

edits = []

# --- Edit 1: Remove D30 → literal scrub arrow (wrong: parallel defenses) ---
old1 = 'arrow(9.35, 4.05, 9.35, 3.25)'
new1 = ''
edits.append((old1, new1))

# --- Edit 2: Replace literal scrub → Consumer with SQL/tool execution → Consumer ---
# literal scrub → Consumer (8.65, 2.5 → 8.65, 1.5) is ambiguous;
# paper says consumer reads the RESULT of SQL/tool execution, so add that arrow.
# Keep literal scrub → Consumer (it represents the scrubbed final answer reaching the consumer).
old2 = 'arrow(8.65, 2.5, 8.65, 1.5)'
new2 = 'arrow(8.65, 2.5, 8.65, 1.5)' + NL + 'arrow(7.5, 1.025, 7.7, 1.025)'
edits.append((old2, new2))

# --- Apply ---
for old, new in edits:
    cnt = src.count(old)
    if cnt != 1:
        print(f"ABORT: expected 1 occurrence of {repr(old)}, found {cnt}")
        sys.exit(1)
    src = src.replace(old, new)
    print(f"OK: replaced {repr(old[:50])}...")

tmp = TARGET + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(src)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, TARGET)
print(f"Written {TARGET} ({len(src)} bytes)")
print("Pass-26 complete: fig1 arrows fixed.")
