"""Simplified 12-point analysis - rules 1-5 only (6-12 already verified)."""
import re

p = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(p, encoding='utf-8').read()
NL = chr(10)

# ---- RULE 2: AI-flavor (simplified) ----
print('=== RULE 2: AI-flavor / first-person / hedging ===')
patterns = [
    (r'\bWe (study|parameterize|ask|evaluate|measure|ran|tested|deploy|show|demonstrate|propose|argue|conclude|find|report|observe|use|leverage|delve|dive)\b', 'We-verb sentence start'),
    (r'\bour (observation|sample|model|threat model|setup|design|method|approach|experiment|benchmark|evaluation|analysis|census|gateway|probes|harness|infrastructure)\b', 'our-Noun possessive'),
    (r'\b(in this paper|to the best of our knowledge|it is worth noting|we believe|we think|we argue|we conjecture)\b', 'hedging cliches'),
    (r'\b(remarkably|notably|importantly|interestingly|surprisingly|crucially|essentially|fundamentally|basically|virtually|literally)\b', 'hedge adverbs'),
    (r'\b(very|rather|fairly|quite|really|actually)\b', 'weak intensifiers'),
]
for pat, label in patterns:
    hits = list(re.finditer(pat, s, re.I))
    if hits:
        print('  %s (%d):' % (label, len(hits)))
        for m in hits[:5]:
            ctx = s[max(0,m.start()-25):m.end()+60].replace(NL,' ')
            print('    ...%s...' % ctx)
    else:
        print('  %s: NONE' % label)
print()

# ---- RULE 3: non-academic ----
print('=== RULE 3: Non-academic / engineering content ===')
na_words = ['HTTP ', 'rolling ', 'non-zero exit', 'gateway-blocked',
            'log-indexing service', 'content-safety classifier',
            'model is not configured', 'key not bound',
            'Bad Request', 'Forbidden', 'Unauthorized', 'Not Found',
            'paid-model', 'open-router', 'production-side', 'deployed-side',
            'real-world', 'real world', 'in-production', 'practical',
            'industry', 'industrial', 'business', 'commercial', 'market',
            'company', 'startup', 'enterprise', 'organization',
            'grader', 'production', 'deployed', 'deployment', 'operator']
for w in na_words:
    cnt = s.count(w)
    if cnt > 0:
        # show first occurrence context
        idx = s.find(w)
        ctx = s[max(0,idx-30):idx+len(w)+60].replace(NL,' ')
        print('  "%s" x%d  e.g. ...%s...' % (w, cnt, ctx))
print()

# ---- RULE 4: uncommon abbreviations ----
print('=== RULE 4: Uncommon abbreviations ===')
# Find all-caps tokens 2-5 chars
allcaps = set(re.findall(r'\b([A-Z]{2,5})\b', s))
common = {'IEEE','TIFS','SQL','CoT','LLM','API','HTTP','HTTPS','URL','URI',
          'GPU','CPU','RAM','OS','CLI','GUI','PDF','PNG','JPG','CSV','JSON',
          'XML','HTML','CSS','JS','TCP','IP','DNS','SSL','TLS','RSA','AES',
          'TPU','NLP','CV','ML','DL','RL','GAN','PCA','SVM','KNN',
          'BERT','GPT','RAG','SDK','IDE','VM','VPN','LAN','WAN',
          'NaN','EOF','UTC','GMT','BIOS','FTP','SMTP','IMAP','POP',
          'ARXiv','DOI','ISBN','ISSN','ACM','USENIX','NDSS','CCS','SP',
          'PCC','RBAC','P2','P3','B1','B2','B3','E1','E2','E4','E6',
          'D0','D23','D30','D31','ROI','KPI','QA','QC','R&D','HR','PR',
          'CI','CD','CT','IO','MO','PO','TO','FO','SO','WO','EO','NO',
          'A','B','C','D','E','F','G','H','I','J','K','L','M',
          'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
          'N112','N25','N84','N268','N371','N196','N32','N13','N24','N18','N16','N8'}
uncommon = sorted(allcaps - common)
for a in uncommon:
    cnt = len(re.findall(r'\b' + a + r'\b', s))
    print('  %s x%d' % (a, cnt))
print()

# ---- RULE 5: self-criticism ----
print('=== RULE 5: Self-criticism / limitations / negative self-ref ===')
neg_terms = [
    'limitation', 'shortcoming', 'deficit', 'weakness', 'vulnerability',
    'flaw', 'gap', 'unresolved', 'unanswered', 'untested', 'unevaluated',
    'unmeasured', 'unverified', 'unvalidated', 'unsupported',
    'inconclusive', 'does not establish', 'does not settle',
    'does not resolve', 'does not prove', 'does not demonstrate',
    'does not show', 'does not confirm', 'cannot be', 'cannot confirm',
    'cannot establish', 'cannot prove', 'cannot validate', 'cannot verify',
    'fail to', 'failure to', 'not fully', 'not completely',
    'not thoroughly', 'not adequately', 'not systematically',
    'remains open', 'remains unresolved', 'remains unanswered',
    'remains unknown', 'remains unexplored', 'remains untested',
    'we do not', 'we did not', 'we cannot', 'we fail', 'we are unable',
    'our limitation', 'our shortcoming', 'our deficit', 'our weakness',
    'our gap', 'our failure', 'our inability',
    'reported as such', 'accessibility constraint',
    'not representative', 'narrow sample', 'not evidence',
    'not resolved', 'has not been evaluated', 'not been evaluated',
    'not been tested', 'not been measured', 'not been validated',
    'not been verified', 'not been confirmed', 'not been established',
    'specific to those families', 'specific to this',
    'not transferable', 'not generalizable', 'not general',
    'not independent', 'not standalone', 'not sufficient',
    'not adequate', 'not appropriate', 'not applicable',
    'not available', 'not accessible', 'not reachable',
    'not configured', 'not bound', 'not found', 'not present',
    'not exposed', 'not observable', 'not measurable',
    'not detectable', 'not reducible', 'not removable',
    'not suppressible', 'not preventable', 'not blockable',
    'not stoppable', 'not avoidable', 'not escapable',
    'not bypassable', 'not circumventable',
]
for t in neg_terms:
    cnt = s.count(t)
    if cnt > 0:
        idx = s.find(t)
        ctx = s[max(0,idx-40):idx+len(t)+80].replace(NL,' ')
        print('  "%s" x%d  ...%s...' % (t, cnt, ctx))
print()

print('=== DONE ===')