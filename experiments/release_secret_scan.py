import os, re, zipfile

zp = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\release\probeleak-bench-v1.0.zip"
z = zipfile.ZipFile(zp)
names = z.namelist()
pat = re.compile(r"(?:sk-[A-Za-z0-9_-]{16,}|ak_[A-Za-z0-9_-]{16,})")
role = re.compile(r"^(prod|admin|internal|service|webhook|test|demo|dev|staging|zh|wxm|crm|billing|api|gateway)")
known_real = [
    "REDACTED_KILO_DOTS3",        # [REDACTED - real key never committed]
    "REDACTED_INTERN_A1",          # [REDACTED - real key never committed]
    "REDACTED_INTERN_S2",          # [REDACTED - real key never committed]
    "REDACTED_GLM53",              # [REDACTED - real key never committed]
    "REDACTED_QWEN38",             # [REDACTED - real key never committed]
    "REDACTED_DSV4FLASHVISION",    # [REDACTED - real key never committed]
    "REDACTED_ATRIA_DAWN",         # [REDACTED - real key never committed]
    "REDACTED_SENSENOVA",          # [REDACTED - real key never committed]
    "REDACTED_DSV4FLASH",          # [REDACTED - real key never committed]
]

real_hits = []
for n in names:
    if n.endswith("/"):
        continue
    try:
        s = z.read(n).decode("latin-1")
    except Exception:
        continue
    for i, line in enumerate(s.splitlines(), 1):
        for m in pat.findall(line):
            body = m.split("-", 1)[1] if m.startswith("sk-") else m
            if role.match(body):
                continue  # synthetic honeypot key
            if any(k in m for k in known_real):
                real_hits.append(("KNOWN-REAL", n, i, m))
            else:
                real_hits.append(("UNKNOWN-HIGH-ENTROPY", n, i, m))

print("=== real-credential-shaped (non-role) hits ===")
print("count:", len(real_hits))
for tag, n, i, m in real_hits:
    print("  [%s] %s:%d  %s" % (tag, n, i, m[:40]))
