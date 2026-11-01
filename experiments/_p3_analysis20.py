"""Full 12-point analysis of p3_tifs.tex at Pass-19 state."""
import re

p = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(p, encoding='utf-8').read()
NL = chr(10)

print('=== PAPER STATE ===')
print('size', len(s), 'bytes / lines', s.count(NL))
print('braces { }', s.count('{'), s.count('}'))
print()

# ---- RULE 6: captions ----
print('=== RULE 6: Captions <=15 words, no formulas ===')
caps = list(re.finditer(r'\\caption\{(.*?)\}', s, re.S))
all_ok = True
for i, m in enumerate(caps):
    cap = m.group(1).replace(NL, ' ').strip()
    words = re.sub(r'\{[^}]*\}', '', cap).split()
    wc = len(words)
    has_math = bool(re.search(r'\\\(|\\\$|\\\[|\\\]|\\eqref|\\mathrm|\\times|\\cdot|\\text|\\%|\\sigma|\\tau|\\rho|\\lambda|\\phi|\\varphi|\\Delta|\\in', cap))
    ok = wc <= 15 and not has_math
    if not ok:
        all_ok = False
    print('  [%s] wc=%2d math=%s  %s' % ('OK' if ok else 'FAIL', wc, has_math, cap[:100]))
print('  ALL PASS:', all_ok)
print()

# ---- RULE 7: notes in captions ----
print('=== RULE 7: No standalone notes in captions ===')
note_pat = re.compile(r'\\emph\{|Note that|note:|Notes:|\\textit\{|\\textbf\{|\\footnote|Counts in parentheses|Reach = number|giving \\$n|\\$n\\$ is the number', re.I)
found = []
for i, m in enumerate(caps):
    if note_pat.search(m.group(1)):
        found.append(i)
print('  Captions with notes:', found if found else 'NONE')
print()

# ---- RULE 8: abstract ----
print('=== RULE 8: Abstract no formulas ===')
ab = re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}', s, re.S)
abt = ab.group(1) if ab else ''
ab_math = bool(re.search(r'\\\$|\\\(|\\\[|\\eqref|\\mathrm|\\times|\\cdot|\\text', abt))
ab_words = len(re.sub(r'\{[^}]*\}', '', abt).split())
print('  Math tokens:', ab_math, '| Words:', ab_words)
print()

# ---- RULE 9: references ----
print('=== RULE 9: References real, recent ===')
refs = re.findall(r'\\bibitem\{(.*?)\}', s)
years = {}
for m in re.finditer(r'\\bibitem\{(.*?)\}(.*?)(?=\\bibitem\{|\\end\{thebibliography\})', s, re.S):
    key = m.group(1)
    block = m.group(2)
    yr = re.search(r'(\d{4})', block)
    y = yr.group(1) if yr else '????'
    years[key] = y
from collections import Counter
yc = Counter(years.values())
print('  Total:', len(refs))
for y in sorted(yc):
    print('   ', y, ':', yc[y])
old = [k for k, v in years.items() if v != '????' and int(v) < 2023]
print('  Pre-2023:', old if old else 'NONE')
print()

# ---- RULE 10: all refs cited ----
print('=== RULE 10: All references cited ===')
cites_raw = re.findall(r'\\cite\{(.*?)\}', s, re.S)
allc = set()
for c in cites_raw:
    for x in c.split(','):
        allc.add(x.strip())
ref_set = set(refs)
uncited = ref_set - allc
orphan = allc - ref_set
print('  Refs:', len(ref_set), 'Cites:', len(allc))
print('  Uncited:', sorted(uncited) if uncited else 'NONE')
print('  Orphan:', sorted(orphan) if orphan else 'NONE')
print()

# ---- RULE 11: figures cited ----
print('=== RULE 11: All figures cited ===')
figs = re.findall(r'\\label\{fig:(.*?)\}', s)
figrefs = set(re.findall(r'\\ref\{fig:(.*?)\}', s))
print('  Fig labels:', figs)
print('  Uncited:', [f for f in figs if f not in figrefs] or 'NONE')
print()

# ---- RULE 12: tables cited ----
print('=== RULE 12: All tables cited ===')
tabs = re.findall(r'\\label\{tab:(.*?)\}', s)
tabrefs = set(re.findall(r'\\ref\{tab:(.*?)\}', s))
print('  Tab labels:', tabs)
print('  Uncited:', [t for t in tabs if t not in tabrefs] or 'NONE')
print()

# ---- RULE 1: hard to understand ----
print('=== RULE 1: Potentially hard-to-understand terms ===')
# Look for technical terms that might need definition
terms = ['verdict triple', 'naive recomputation', 'five-strategy ladder',
         'boundary condition', 'gate-fail', 'schema-hiding arm', 'consumer arm',
         'real-trace defense test', 'security audit run', 'co-evolution',
         'model-driven pooling', 'contextual bandit', 'Wilson 95',
         'Jeffreys prior', 'McNemar', 'Fisher exact', 'paired McNemar',
         'one-sided 95% upper bound', 'leak-equivalent', 'honeypot',
         'dual-channel honeypot judge', 'reasoning trace', 'final answer',
         'stacking', 'joint residual', 'discount factor',
         'output-side filtering', 'input-side rewriting', 'literal scrubbing',
         'channel visibility', 'effective attack', 'scorable repeat']
for t in terms:
    cnt = s.count(t)
    if cnt > 0:
        print('  "%s" x%d' % (t, cnt))
print()

# ---- RULE 2: AI flavor ----
print('=== RULE 2: AI-flavor phrases ===')
ai_pat = re.compile(r'\b(We (study|parameterize|ask|evaluate|measure|ran|tested|deploy|show|demonstrate|propose|argue|conclude|find|report|observe|measure|use|leverage|unlock|delve|dive)\b|\bour (observation|sample|model|threat model|setup|design|method|approach|experiment|benchmark|evaluation|analysis|census|gateway|probes|harness|infrastructure)\b|\b(in this paper|to the best of our knowledge|it is worth noting|we believe|we think|we argue|we conjecture)\b|\b(remarkable|notably|importantly|interestingly|surprisingly|crucially|essentially|fundamentally|essentially|basically|basically|virtually|literally|actually|really|very|quite|rather|fairly)\b', re.I)
ai_hits = []
for m in ai_pat.finditer(s):
    ctx = s[max(0,m.start()-20):m.end()+60].replace(NL,' ')
    ai_hits.append(ctx)
if ai_hits:
    for h in ai_hits[:20]:
        print('  ...%s...' % h)
else:
    print('  NONE found')
print()

# ---- RULE 3: non-academic ----
print('=== RULE 3: Non-academic content ===')
na_pat = re.compile(r'HTTP \d|rolling 60-second|non-zero exit|gateway-blocked|log-indexing service|content-safety classifier|model is not configured|key not bound|Bad Request|Forbidden|Unauthorized|Not Found|paid-model|open-router|grader|production-side|deployed-side|real-world|real world|in-production|practical|practically|industry|industrial|business|commercial|market|company|startup|enterprise|organization|organizational')
na_hits = []
for m in na_pat.finditer(s):
    ctx = s[max(0,m.start()-10):m.end()+50].replace(NL,' ')
    na_hits.append(ctx)
if na_hits:
    seen = set()
    for h in na_hits:
        if h not in seen:
            seen.add(h)
            print('  ...%s...' % h)
else:
    print('  NONE found')
print()

# ---- RULE 4: uncommon abbreviations ----
print('=== RULE 4: Uncommon abbreviations ===')
abbr_pat = re.compile(r'\b([A-Z]{2,5})\b|\b[A-Z][a-z]+[A-Z]\b')
abbrs = {}
for m in abbr_pat.finditer(s):
    a = m.group(0)
    if a not in abbrs:
        abbrs[a] = 0
    abbrs[a] += 1
# Filter common ones
common = {'IEEE', 'TIFS', 'SQL', 'CoT', 'LLM', 'API', 'HTTP', 'HTTPS', 'URL', 'URI',
          'GPU', 'CPU', 'RAM', 'OS', 'CLI', 'GUI', 'PDF', 'PNG', 'JPG', 'CSV', 'JSON',
          'XML', 'HTML', 'CSS', 'JS', 'TCP', 'IP', 'DNS', 'SSL', 'TLS', 'RSA', 'AES',
          'GPU', 'TPU', 'NLP', 'CV', 'ML', 'DL', 'RL', 'GAN', 'PCA', 'SVM', 'KNN',
          'BERT', 'GPT', 'RAG', 'API', 'SDK', 'IDE', 'VM', 'VPN', 'LAN', 'WAN',
          'NaN', 'EOF', 'UTC', 'GMT', 'BIOS', 'FTP', 'SMTP', 'IMAP', 'POP',
          'ARXiv', 'DOI', 'ISBN', 'ISSN', 'ACM', 'IEEE', 'USENIX', 'NDSS',
          'CCS', 'S&P', 'ODS', 'ODS', 'PCC', 'RBAC', 'P2', 'P3', 'B1', 'B2', 'B3',
          'E1', 'E2', 'E4', 'E6', 'D0', 'D23', 'D30', 'D31', 'N=112', 'N=25', 'N=84',
          'N=268', 'N=371', 'N=196', 'N=32', 'N=13', 'N=24', 'N=18', 'N=16', 'N=8',
          'ROI', 'KPI', ' MVP', 'QA', 'QC', 'R&D', 'HR', 'PR', 'AD', 'BA', 'CA',
          'CI', 'CD', 'CT', 'IO', 'MO', 'PO', 'TO', 'FO', 'SO', 'WO', 'EO', 'NO',
          'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
          'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}
uncommon = {a: c for a, c in abbrs.items() if a not in common and len(a) >= 2}
for a in sorted(uncommon, key=lambda x: -uncommon[x])[:30]:
    print('  %s x%d' % (a, uncommon[a]))
print()

# ---- RULE 5: self-criticism ----
print('=== RULE 5: Self-criticism / negative self-reference ===')
neg_pat = re.compile(r'(limitation|shortcoming|deficit|weakness|vulnerability|flaw|gap|unresolved|unanswered|untested|unevaluated|unmeasured|unverified|unvalidated|unsupported|inconclusive|does not (establish|settle|resolve|prove|demonstrate|show|confirm)|cannot (be |confirm|establish|prove|validate|verify)|fail(s|ed|ure)? (to |in )?(establish|resolve|validate|confirm|prove)|not (fully|completely|thoroughly|adequately|sufficiently|systematically)|remains? (an? )?(open|unresolved|unanswered|unknown|unexplored|untested|unevaluated)|we (do not|did not|cannot|fail|unable|skip|omit|ignore|avoid|leave|refuse|decline)|our (limitation|shortcoming|deficit|weakness|gap|failure|inability|unwillingness)|the (limitation|shortcoming|deficit|weakness|gap|flaw|vulnerability)|reported as (such|a boundary condition)|accessibility constraint)', re.I)
neg_hits = []
for m in neg_pat.finditer(s):
    start = max(0, m.start() - 40)
    end = min(len(s), m.end() + 80)
    ctx = s[start:end].replace(NL, ' ')
    neg_hits.append(ctx)
if neg_hits:
    seen = set()
    for h in neg_hits:
        if h not in seen:
            seen.add(h)
            print('  ...%s...' % h)
else:
    print('  NONE found')
print()

print('=== ANALYSIS COMPLETE ===')