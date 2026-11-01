"""Count abstract-word variants with the tifs_audit.words() rule."""
import re


def words(text):
    t = re.sub(r"\\[a-zA-Z]+\*?", " ", text)
    t = re.sub(r"[{}%$]", " ", t)
    return [w for w in t.split() if re.search(r"[A-Za-z0-9]", w)]


CAND = r"""LLM agents mediate database access in deployed settings, yet evaluations
treat the model as one output channel, assume defenses compose multiplicatively,
and rely on simulated or single-model evidence. Across 371 attack responses on a
real reasoning-model gateway with a 35-probe channel-isolated suite, we measure
three consequences. (1) Credential leakage is native to the reasoning channel: on
268 fresh-probe responses it leaks at 14.55\% (95\% CI [10.83, 19.27]) while the
final-answer channel shows none (0/268; one-sided 95\% bound 1.1\%). Clean final
answers are a probe-set property: on public-benchmark probes the final channel
leaks at 62.5\%, and the pooled rate mixes 14.55\% fresh with 100\% under
repetition. (2) A calibrated-model bound caps defense stacking at 4.48-fold the
independence prediction, and the measured stack collapses to its
stronger layer. (3) Output-side filtering depends on consumer visibility: a
downstream consumer recovers nothing from final answers but extracts a mean 11.2
of 15 honeypot keys from reasoning traces, which three output-side filters
nullify. The asymmetry replicates on an independent gateway---including the
primary family under separate hosting (54.2\% versus 53.6\%)---and paraphrases
leak as often or more (83\%), so it is neither gateway-specific nor
phrasing-specific. Four forensic implications follow for logging, detection,
containment, and evidence integrity."""

print("candidate words:", len(words(CAND)))
