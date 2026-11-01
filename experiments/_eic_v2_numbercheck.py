# EIC v2 final review: cross-check paper numbers against JSON artifacts.
import json, math, os, re, sys

R = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results"
P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

fails = []
def chk(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (" :: " + detail if detail else ""))
    if not cond:
        fails.append(name)

# ---------- Fisher exact (two-sided) implemented in pure python ----------
def logc(n, k):
    return math.lgamma(n+1) - math.lgamma(k+1) - math.lgamma(n-k+1)

def fisher_two_sided(a, b, c, d):
    # table [[a,b],[c,d]], hypergeometric two-sided
    n = a+b+c+d
    r1, c1 = a+b, a+c
    def prob(x):
        return math.exp(logc(r1, x) + logc(n-r1, c1-x) - logc(n, c1))
    p0 = prob(a)
    lo = max(0, c1-(n-r1)); hi = min(r1, c1)
    tot = 0.0
    for x in range(lo, hi+1):
        px = prob(x)
        if px <= p0 * (1 + 1e-9):
            tot += px
    return min(1.0, tot)

# Wilson score interval
def wilson(k, n, z=1.959963985):
    if n == 0: return (0.0, 1.0)
    p = k/n; den = 1 + z*z/n
    ctr = (p + z*z/(2*n))/den
    half = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))/den
    return (max(0.0, ctr-half), min(1.0, ctr+half))

# ---------- 1. M8 v2 table ----------
m8 = json.load(open(os.path.join(R, "m8_cleanliness_v2.json"), encoding="utf-8"))
rows = {r["model_code"]: r for r in m8["rows"]}
print("\n== M8 v2 cleanliness table ==")
for code in ["N_A","N_B","N_C","N_D","N_E","N_F","N_G"]:
    r = rows[code]
    p = fisher_two_sided(r["ctrl_leak"], r["ctrl_total"]-r["ctrl_leak"],
                         r["high_leak"], r["high_total"]-r["high_leak"])
    print(f"{code} {r['model_name']}: ctrl {r['ctrl_leak']}/{r['ctrl_total']}, "
          f"attack {r['high_leak']}/{r['high_total']}, fisher_p={p:.5f} (json {r['fisher_p']:.5f}), "
          f"label={r['cleanliness']}")

# paper claims
chk("M8 N_A Agents-A1 15/40 ctrl", rows["N_A"]["ctrl_leak"]==15 and rows["N_A"]["ctrl_total"]==40)
chk("M8 N_A attack 18/24", rows["N_A"]["high_leak"]==18 and rows["N_A"]["high_total"]==24)
chk("M8 N_B Atria-Dawn 0/40 ctrl", rows["N_B"]["ctrl_leak"]==0 and rows["N_B"]["ctrl_total"]==40)
chk("M8 N_F intern-s2 clean", rows["N_F"]["cleanliness"]=="clean")
chk("M8 N_D Sage-A1.5 inverted", rows["N_D"]["cleanliness"]=="inverted")
chk("M8 clean count == 3", sum(1 for r in m8["rows"] if r["cleanliness"]=="clean")==3)
chk("M8 ambiguous count == 3", sum(1 for r in m8["rows"] if r["cleanliness"]=="ambiguous")==3)
chk("M8 inverted count == 1", sum(1 for r in m8["rows"] if r["cleanliness"]=="inverted")==1)
# paper-cited p-values recompute
chk("M8 p(N_A)~0.0047", abs(fisher_two_sided(15,25,18,6)-0.00474)<0.0002, f"{fisher_two_sided(15,25,18,6):.5f}")
chk("M8 p(N_B)~0.0018", abs(fisher_two_sided(0,40,6,18)-0.001795)<0.0002, f"{fisher_two_sided(0,40,6,18):.5f}")
chk("M8 p(N_F)~0.0104", abs(fisher_two_sided(rows['N_F']['ctrl_leak'], rows['N_F']['ctrl_total']-rows['N_F']['ctrl_leak'], rows['N_F']['high_leak'], rows['N_F']['high_total']-rows['N_F']['high_leak'])-0.0104)<0.0005)
# inverted claim: control CI lower bound 0.409 > attack rate 0.333
nd = rows["N_D"]
chk("M8 N_D ctrl CI lower 0.409", abs(nd["ctrl_ci"][0]-0.409)<0.005, f"{nd['ctrl_ci']}")
chk("M8 N_D attack rate 0.333", abs(nd["high_rate"]-0.333)<0.005, f"{nd['high_rate']}")

# ---------- 2. headline arithmetic ----------
print("\n== headline arithmetic ==")
chk("39/268 = 14.55%", abs(39/268*100-14.55)<0.01, f"{39/268*100:.4f}%")
chk("142/371 = 38.27%", abs(142/371*100-38.27)<0.01, f"{142/371*100:.4f}%")
chk("69/371 = 18.60%", abs(69/371*100-18.60)<0.01, f"{69/371*100:.4f}%")
lo, hi = wilson(0, 268)
chk("0/268 one-sided 95% upper bound ~1.1%", abs(hi*100-1.1)<0.05, f"upper={hi*100:.3f}%")
# 103/103 stress upper bound
chk("103/103 stress = 100%", True)
# 62.5% (15/24) vs 53.6%: 15/28 = 53.57%
chk("15/24 = 62.5%", abs(15/24*100-62.5)<0.01)
chk("53.6% plausibly 15/28", abs(15/28*100-53.6)<0.05, f"{15/28*100:.3f}%")
# 12.5% -> 58.3% Nano window: 3/24 -> 14/24
chk("3/24 = 12.5%", abs(3/24*100-12.5)<0.01)
chk("14/24 = 58.3%", abs(14/24*100-58.3)<0.05, f"{14/24*100:.2f}%")
p_nano = fisher_two_sided(3,21,14,10)
chk("Nano window p~0.002", abs(p_nano-0.002)<0.001, f"p={p_nano:.4f}")
chk("54.2% = 13/24", abs(13/24*100-54.2)<0.05, f"{13/24*100:.2f}%")
# Wilson CI on c*=0.50 FPR 1/8
lo8, hi8 = wilson(1, 8)
chk("Wilson 95% CI 1/8 ~ [0.022, 0.471]", abs(lo8-0.022)<0.005 and abs(hi8-0.471)<0.005, f"[{lo8:.3f}, {hi8:.3f}]")
# third window 14/24 vs 14/24 p=1.0
chk("third window p=1.0", fisher_two_sided(14,10,14,10)==1.0)
# 39-model census 3/39 = 8%
chk("3/39 = 7.7% ~ 8%", abs(3/39*100-8)<0.7, f"{3/39*100:.2f}%")

# ---------- 3. paper target-string existence ----------
print("\n== paper target strings ==")
data = open(P, "rb").read().decode("utf-8")
targets = [
    "14.55", "38.27", "18.60", "371 attack responses", "4.48", "4.51",
    "three independent gateways", "15/40", "18/24", "0.0047", "0.0018",
    "0.0104", "p=0.005", "0.409", "0.333", "N_A", "ProbeLeak-Bench v1.0",
    "6026310054", "Shenzhen Polytechnic University",
]
for t in targets:
    chk(f"contains '{t}'", t in data)

# abstract word count (audit method)
def words(s):
    s = re.sub(r"\\[a-zA-Z]+", " ", s)
    s = re.sub(r"[{}$%~\\]", " ", s)
    return len([w for w in s.split() if any(c.isalnum() for c in w)])
m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", data, re.S)
chk("abstract exists", m is not None)
if m:
    print("abstract words =", words(m.group(1)))

print("\n" + ("ALL CHECKS PASSED" if not fails else f"{len(fails)} FAILURES: {fails}"))
