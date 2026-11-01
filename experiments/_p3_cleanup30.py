"""Pass-30: Remove 8 orphaned bibitems left by Pass-29 (no longer cited)."""
import os, sys

TEX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "paper", "p3_tifs.tex")

with open(TEX, "r", encoding="utf-8") as f:
    tex = f.read()

# 8 orphaned bibitems to remove (each is a \bibitem{key}...\n...up to the next \bibitem or blank line)
orphans = [
    "savani2025", "tian2025", "wmdp2024", "inan2023",
    "llamaguard2024", "conclaude2025", "dpo2023", "safetybench2024",
]

# Build regex to match each orphan bibitem block
# Pattern: \bibitem{key} followed by lines until the next \bibitem or end of bibliography
import re

for key in orphans:
    # Match \bibitem{key} ... up to (but not including) the next \bibitem or end
    pattern = r'\\bibitem\{' + re.escape(key) + r'\}.*?(?=\\bibitem|\Z)'
    matches = re.findall(pattern, tex, re.DOTALL)
    if len(matches) != 1:
        print(f"ABORT: {key}: expected 1 match, found {len(matches)}")
        sys.exit(1)
    tex = re.sub(pattern, '', tex, flags=re.DOTALL)
    print(f"OK: removed {key}")

# Clean up any double blank lines left behind
tex = re.sub(r'\n\n\n+', '\n\n', tex)

tmp = TEX + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(tex)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, TEX)
print(f"Written {TEX} ({len(tex)} bytes)")
print("Pass-30 complete.")