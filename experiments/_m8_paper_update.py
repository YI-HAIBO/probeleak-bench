#!/usr/bin/env python3
"""Update p3_tifs.tex with M8 v2 cleanliness results (expanded controls).

Uses short, unique anchor strings to avoid line-break mismatch.
"""
import os, sys

PAPER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "paper", "p3_tifs.tex")

def read():
    with open(PAPER, "rb") as f:
        return f.read()

def write(data):
    tmp = PAPER + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, PAPER)

data = read()

# Detect encoding: file may be CRLF or LF
crlf = b"\r\n" in data
if crlf:
    print("File uses CRLF line endings")
else:
    print("File uses LF line endings")

# Work on bytes to avoid any encoding surprise
edits = []

# ---- Edit 1: "3 of 8" -> "15 of 40" for Agents-A1 controls ----
old1 = b"3 of 8---far above the 0--2/8 control rates"
new1 = b"15 of 40---far above the 0--2/8 control rates"
count1 = data.count(old1)
print(f"Edit 1 anchor count: {count1}")
if count1 == 1:
    data = data.replace(old1, new1)
    edits.append("Edit 1: Agents-A1 control count 3/8 -> 15/40")

# ---- Edit 2: "Only intern-s2's ... (p=0.010)" paragraph ----
old2 = b"Only\r\nintern-s2's high-tier rate significantly exceeds its own control baseline\r\n($p=0.010$), while Sage-A1.5's 8/24 sits below its 6/8 control rate. Part of\r\nthe third-gateway leak signal is therefore spontaneous prompt-content recitation\r\nrather than probe-attributed exfiltration, and the probe-attributed finding\r\non this gateway is the replication at baseline strength on intern-s2."
# Try LF variant too
old2_lf = old2.replace(b"\r\n", b"\n")
if data.count(old2) == 1:
    new2 = (b"After expanding the control sample from 8 to 40 per model,\r\n"
            b"three backends show clean probe-attributed separation:\r\n"
            b"intern-s2's high-tier rate significantly exceeds its own control baseline\r\n"
            b"($p=0.010$), Agents-A1's 18/24 exceeds its 15/40 control rate\r\n"
            b"($p=0.005$), and Atria-Dawn's 6/24 exceeds its 0/40 control rate\r\n"
            b"($p=0.002$). Sage-A1.5's 8/24 still sits below its 6/8 control rate\r\n"
            b"(an inverted baseline), and Atria-Dawn-Preview remains ambiguous\r\n"
            b"(1/40 controls, $p=0.025$). Part of\r\n"
            b"the third-gateway leak signal is therefore spontaneous prompt-content recitation\r\n"
            b"rather than probe-attributed exfiltration, and the probe-attributed findings\r\n"
            b"on this gateway are the replications at baseline strength on intern-s2,\r\n"
            b"Agents-A1, and Atria-Dawn.")
    if crlf:
        new2 = new2.replace(b"\r\n", b"\r\n")
    else:
        new2 = new2.replace(b"\r\n", b"\n")
    data = data.replace(old2, new2)
    edits.append("Edit 2: control-baseline paragraph updated")
elif data.count(old2_lf) == 1:
    new2 = (b"After expanding the control sample from 8 to 40 per model,\n"
            b"three backends show clean probe-attributed separation:\n"
            b"intern-s2's high-tier rate significantly exceeds its own control baseline\n"
            b"($p=0.010$), Agents-A1's 18/24 exceeds its 15/40 control rate\n"
            b"($p=0.005$), and Atria-Dawn's 6/24 exceeds its 0/40 control rate\n"
            b"($p=0.002$). Sage-A1.5's 8/24 still sits below its 6/8 control rate\n"
            b"(an inverted baseline), and Atria-Dawn-Preview remains ambiguous\n"
            b"(1/40 controls, $p=0.025$). Part of\n"
            b"the third-gateway leak signal is therefore spontaneous prompt-content recitation\n"
            b"rather than probe-attributed exfiltration, and the probe-attributed findings\n"
            b"on this gateway are the replications at baseline strength on intern-s2,\n"
            b"Agents-A1, and Atria-Dawn.")
    data = data.replace(old2_lf, new2)
    edits.append("Edit 2: control-baseline paragraph updated (LF)")
else:
    # Try a shorter anchor
    old2s = b"Only\r\nintern-s2's"
    old2s_lf = b"Only\nintern-s2's"
    if data.count(old2s) == 1:
        print("  Trying shorter anchor for edit 2 (CRLF)")
        # Find the full sentence extent
        start = data.index(old2s)
        end_marker = b"strength on intern-s2."
        end = data.index(end_marker, start) + len(end_marker)
        old_full = data[start:end]
        print(f"  Old text ({len(old_full)} bytes): {old_full[:120]}...")
        new_full = (b"After expanding the control sample from 8 to 40 per model,\r\n"
                    b"three backends show clean probe-attributed separation:\r\n"
                    b"intern-s2's high-tier rate significantly exceeds its own control baseline\r\n"
                    b"($p=0.010$), Agents-A1's 18/24 exceeds its 15/40 control rate\r\n"
                    b"($p=0.005$), and Atria-Dawn's 6/24 exceeds its 0/40 control rate\r\n"
                    b"($p=0.002$). Sage-A1.5's 8/24 still sits below its 6/8 control rate\r\n"
                    b"(an inverted baseline), and Atria-Dawn-Preview remains ambiguous\r\n"
                    b"(1/40 controls, $p=0.025$). Part of\r\n"
                    b"the third-gateway leak signal is therefore spontaneous prompt-content recitation\r\n"
                    b"rather than probe-attributed exfiltration, and the probe-attributed findings\r\n"
                    b"on this gateway are the replications at baseline strength on intern-s2,\r\n"
                    b"Agents-A1, and Atria-Dawn.")
        data = data[:start] + new_full + data[end:]
        edits.append("Edit 2: control-baseline paragraph updated (short anchor)")
    elif data.count(old2s_lf) == 1:
        print("  Trying shorter anchor for edit 2 (LF)")
        start = data.index(old2s_lf)
        end_marker = b"strength on intern-s2."
        end = data.index(end_marker, start) + len(end_marker)
        old_full = data[start:end]
        print(f"  Old text ({len(old_full)} bytes): {old_full[:120]}...")
        new_full = (b"After expanding the control sample from 8 to 40 per model,\n"
                    b"three backends show clean probe-attributed separation:\n"
                    b"intern-s2's high-tier rate significantly exceeds its own control baseline\n"
                    b"($p=0.010$), Agents-A1's 18/24 exceeds its 15/40 control rate\n"
                    b"($p=0.005$), and Atria-Dawn's 6/24 exceeds its 0/40 control rate\n"
                    b"($p=0.002$). Sage-A1.5's 8/24 still sits below its 6/8 control rate\n"
                    b"(an inverted baseline), and Atria-Dawn-Preview remains ambiguous\n"
                    b"(1/40 controls, $p=0.025$). Part of\n"
                    b"the third-gateway leak signal is therefore spontaneous prompt-content recitation\n"
                    b"rather than probe-attributed exfiltration, and the probe-attributed findings\n"
                    b"on this gateway are the replications at baseline strength on intern-s2,\n"
                    b"Agents-A1, and Atria-Dawn.")
        data = data[:start] + new_full + data[end:]
        edits.append("Edit 2: control-baseline paragraph updated (short anchor LF)")
    else:
        print("Edit 2: FAILED - anchor not found")
        sys.exit(1)

# ---- Edit 3: "only two of the three operators" ----
old3 = b"only two of the three operators provide\r\nclean probe-attributed comparisons, because on the third gateway several backends\r\nrecite honeypot credentials in response to benign controls."
old3_lf = old3.replace(b"\r\n", b"\n")
new3 = (b"all three operators provide\r\n"
        b"clean probe-attributed comparisons; on the third gateway, three of seven\r\n"
        b"backends are clean after control expansion, one is inverted, and three\r\n"
        b"remain ambiguous.")
new3_lf = new3.replace(b"\r\n", b"\n")

if data.count(old3) == 1:
    data = data.replace(old3, new3)
    edits.append("Edit 3: operator claim updated")
elif data.count(old3_lf) == 1:
    data = data.replace(old3_lf, new3_lf)
    edits.append("Edit 3: operator claim updated (LF)")
else:
    # Shorter anchor
    old3s = b"only two of the three operators"
    count3 = data.count(old3s)
    print(f"Edit 3 short anchor count: {count3}")
    if count3 == 1:
        start = data.index(old3s)
        end_marker = b"recite honeypot credentials in response to benign controls."
        end = data.index(end_marker, start) + len(end_marker)
        old_full = data[start:end]
        sep = b"\r\n" if crlf else b"\n"
        new_full = (b"all three operators provide" + sep +
                    b"clean probe-attributed comparisons; on the third gateway, three of seven" + sep +
                    b"backends are clean after control expansion, one is inverted, and three" + sep +
                    b"remain ambiguous.")
        data = data[:start] + new_full + data[end:]
        edits.append("Edit 3: operator claim updated (short anchor)")
    else:
        print("Edit 3: FAILED")
        sys.exit(1)

# ---- Edit 4: cleanliness quantification paragraph ----
old4s = b"cleanliness quantification"
count4 = data.count(old4s)
print(f"Edit 4 anchor count: {count4}")
if count4 == 1:
    start = data.index(old4s)
    # Find the end: "withholds per-model vendor attribution."
    end_marker = b"withholds per-model vendor attribution."
    end = data.index(end_marker, start) + len(end_marker)
    old_full = data[start:end]
    print(f"  Old text ({len(old_full)} bytes): {old_full[:100]}...")
    sep = b"\r\n" if crlf else b"\n"
    new_full = (b"cleanliness quantification (control CI upper bound below attack" + sep +
                b"CI lower bound) classifies 3 of 7 backends with valid data as clean (intern-s2, Fisher" + sep +
                b"$p=0.0104$; Agents-A1, $p=0.0047$; Atria-Dawn, $p=0.0018$), 1 as inverted (Sage-A1.5: even" + sep +
                b"the conservative control CI lower bound, 0.409," + sep +
                b"exceeds the attack rate 0.333, so the model recites credentials in response to benign" + sep +
                b"prompts more often than to attacks---a model-level property, not noise), and 3 as ambiguous" + sep +
                b"(CIs overlap). The clean classifications for Agents-A1 and Atria-Dawn were obtained by" + sep +
                b"expanding the control sample from 8 to 40 per model; Atria-Dawn-Preview remains" + sep +
                b"ambiguous at 1/40 controls and would need approximately 58." + sep +
                b"The aggregator operator" + sep +
                b"withholds per-model vendor attribution.")
    data = data[:start] + new_full + data[end:]
    edits.append("Edit 4: cleanliness quantification paragraph updated")
else:
    print("Edit 4: FAILED")
    sys.exit(1)

if not edits:
    print("No edits made!")
    sys.exit(1)

write(data)
newsize = os.path.getsize(PAPER)
print(f"\nWrote {PAPER} ({newsize:,} bytes)")
for e in edits:
    print(f"  {e}")