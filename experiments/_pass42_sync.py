import hashlib, os, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper"
DST = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\submission_2026-10-21"

def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()

pairs = [("p3_tifs.tex", "p3_tifs.tex"), ("p3_tifs.pdf", "p3_tifs.pdf")]
for src_name, dst_name in pairs:
    s = os.path.join(SRC, src_name)
    d = os.path.join(DST, dst_name)
    shutil.copy2(s, d)
    print(f"{src_name}: {os.path.getsize(s)} bytes, md5 {md5(s)}")
    assert md5(s) == md5(d), f"MD5 mismatch for {dst_name}"
print("submission package synced, MD5-verified.")
