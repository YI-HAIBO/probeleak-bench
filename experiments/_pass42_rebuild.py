import os, subprocess, time

EXE = r"C:\CTEX\MiKTeX\miktex\bin\x64\pdflatex.exe"
DIR = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper"
JOB = "p3_tifs"

env = os.environ.copy()
parts = env.get("PATH", "").split(os.pathsep)
clean = [p for p in parts if p.strip() and not os.path.isfile(p)]
env["PATH"] = os.pathsep.join(clean)

for i in range(3):
    r = subprocess.run([EXE, "-interaction=nonstopmode", f"{JOB}.tex"],
                       cwd=DIR, env=env, capture_output=True, timeout=240)
    print(f"pass {i+1}: rc={r.returncode}")
    if r.returncode != 0:
        print(r.stdout.decode("utf-8", "replace")[-3000:])
        raise SystemExit(1)

pdf = os.path.join(DIR, JOB + ".pdf")
log = os.path.join(DIR, JOB + ".log")
print("pdf size:", os.path.getsize(pdf))
print("pdf mtime:", time.ctime(os.path.getmtime(pdf)))
data = open(log, "r", encoding="utf-8", errors="replace").read()
for tok in ["Fatal", "Overfull", "Underfull", "Undefined"]:
    print(tok, data.count(tok))
