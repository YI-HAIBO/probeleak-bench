"""Pass-39 follow-up: refresh the workspace MEMORY.md remaining-work section.

Single atomic script (same-file edits must not be issued in parallel).
Reads/writes bytes so CRLF line endings are preserved verbatim.
Every replacement asserts exactly one hit; aborts on any mismatch.
"""
import sys

P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\.workbuddy\memory\MEMORY.md"

EDITS = []

# 1. Pass-39 line had picked up the stale tail of the old Pass-38 line.
EDITS.append((
    "\u65b0\u589e\u7a97\u53e3\u884c\u79f0 (window 3)\u3002\uff1a15 \u9875 563,770 B\uff0c3 \u904d "
    "pdflatex 0 \u9519\u8bef\uff0caudit \u5168\u8fc7\uff08abstract 200 \u8bcd\u3001\u6b63\u6587 "
    "13,002 \u8bcd\u30017 \u56fe 7 \u8868 1 \u5f0f\u300144 \u5f15 44/44 cite \u95ed\u5408\u3001"
    "fatal/overfull/undef 0\uff09\uff0c\u6295\u7a3f\u5305\u5df2\u540c\u6b65\uff08\u65e0\u5b64\u513f"
    "\u56fe\uff09\u3002Pass-37 \u65f6\u4e3a 561,705 B / \u6b63\u6587 12,622 \u8bcd\u3002",
    "\u65b0\u589e\u7a97\u53e3\u884c\u79f0 (window 3)\u3002",
))

# 2. Submission package line still said 15 pages / Pass-37.
EDITS.append((
    "p3_tifs.tex+pdf\uff0815 \u9875\uff0cPass-37 \u5df2\u540c\u6b65\uff09+7 \u56fe\u4ef6 "
    "PDF+COVER_LETTER.md+README.md\uff08\u542b Pass-36/37 \u6bb5\u843d\uff09",
    "p3_tifs.tex+pdf\uff0816 \u9875\uff0cPass-39 \u5df2\u540c\u6b65\uff09+7 \u56fe\u4ef6 "
    "PDF+COVER_LETTER.md\uff08Pass-39 \u91cd\u5199\uff1a\u9875\u6570/\u8bcd\u6570/\u56fe\u8868/"
    "\u5f15\u7528\u6570\u4e0e\u4e09 operator \u53e3\u5f84\u5168\u90e8\u5bf9\u9f50\uff09+"
    "README.md\uff08\u542b Pass-36/37/39 \u6bb5\u843d\uff09",
))

# 3. The "real RL attacker + real defense validation" bullet is now done for the
#    real-model attacker; what actually remains is the co-evolution-against-
#    adaptive-defense gap.
EDITS.append((
    "- \u771f\u5b9e RL \u653b\u51fb\u8005\u63a5\u5165\u5171\u8fdb\u5316\u81c2\u3001D23\u2032/"
    "\u5806\u53e0\u771f\u5b9e\u9a8c\u8bc1\uff08\u5747\u5361 B2\uff1a\u5f53\u524d\u65e0\u7b2c\u4e8c"
    "\u63a8\u7406\u6a21\u578b\u5e38\u9a7b\uff0c\u4ec5\u7a97\u53e3\u6027\u53ef\u7528\uff09\u3002",
    "- \u5171\u8fdb\u5316\u81c2\u4e0e D23\u2032/D30 \u771f\u5b9e\u9a8c\u8bc1\u5747\u5df2\u5b8c\u6210"
    "\uff08\u89c1 #103/#104\uff09\uff0c\u4f46\u8bba\u6587\u9650\u5236\u53e5\u6240\u4f9d\u8d56\u7684"
    "\u6700\u5927\u79d1\u5b66\u7f3a\u53e3\u4ecd\u5728\uff1a\u5171\u8fdb\u5316\u653b\u51fb\u8005\u6253"
    "\u81ea\u9002\u5e94\u9632\u5fa1\u672a\u5b9e\u6d4b\uff08E7b \u53ea\u5728\u65e0\u9632\u5fa1\u76ee"
    "\u6807\u4e0a\u6bd4\u4e86\u5171\u8fdb\u5316 vs \u56fa\u5b9a\u81c2\uff0cE8 \u53ea\u7528\u56fa\u5b9a"
    "\u8bed\u6599\u8fc7\u4e86 D23\u2032/D30\uff0c\u4e24\u8005\u672a\u63a5\u8d77\u6765\uff1bE9 \u5728"
    "\u8dd1\uff09\u3002\u5176\u4f59\u5df2\u5728\u6b63\u6587\u5982\u5b9e\u6807\u6ce8\u4f46\u672a\u5b9e"
    "\u9a8c\u586b\u4e0a\uff1aD30 \u662f oracle \u7ea2action\uff080% bypass \u4e3a\u4e0a\u754c\uff09\u3001"
    "D23\u2032 \u7528\u8bcd\u888b\u4f59\u5f26\u800c\u975e learned embedding\u3001\u826f\u6027\u6837\u672c"
    "\u592a\u5c0f\uff08consumer 4 \u6761 / E8 \u5bf9\u7167 8 \u6761\uff0cFPR CI \u5bbd\uff09\u3001"
    "split-across-boundary \u6cc4\u6f0f\u4ecd\u662f\u53c2\u6570\u5316\u3002RL \u9a71\u52a8\u653b\u51fb"
    "\u8005\u4ecd\u672a\u63a5\uff08\u73b0\u6709 attacker = \u56fa\u5b9a\u6539\u5199\u63d0\u793a + Thompson "
    "\u62c9\u81c2\uff0c\u975e\u8bad\u7ec3\u5faa\u73af\uff09\u3002",
))

# 4. B2 is no longer truncated.
EDITS.append((
    "- B2 \u590d\u6d3b\u88c1\u5b9a\uff082026-10-24 \u6ce2 2\uff0c\u5df2\u5e76\u5165 Pass-37\uff09\uff1a"
    "kilo \u7f51\u5173\u533f\u540d\u514d\u8d39\u7a97\u53e3\u63d0\u4f9b nemotron-3.5-lightning\uff0c9 "
    "\u96c6\uff087 \u53ef\u7528\uff09\u9996\u96c6\u5373\u6cc4\u6f0f\uff1b\u7a97\u53e3\u77ed\u3001\u6837\u672c"
    "\u5c0f\uff0c\u5df2\u6309\u622a\u65ad\u53e3\u5f84\u5199\u5165\u8bba\u6587\u5e76\u6807\u6ce8 g2 "
    "\u6743\u91cd\u8fd1\u96f6\u3002\u540e\u7eed\u82e5\u7a97\u53e3\u518d\u5f00\uff1a\u8865\u6ee1 "
    "40 \u96c6\u5e76\u66f4\u65b0 Section V-D \u6570\u5b57\u3002",
    "- B2 \u5df2\u8865\u6ee1 40/40\uff08#103\uff0c2026-10-25\uff0c\u5df2\u5e76\u5165 Pass-39\uff09\uff1a"
    "kilo \u533f\u540d\u7a97\u53e3\u590d\u5f00\uff0cCoT 26/38=68.4%\u3001\u9996\u6f0f ep1\u3001"
    "thinking-leak 18/21\u3001final 0\u30015 gates \u5168\u8fc7\uff1b\u8bba\u6587\u300c9/40 \u622a\u65ad "
    "7 usable\u300d\u65e7\u53e3\u5f84\u5df2\u66ff\u6362\u3002",
))

# 5. The "must update / risks overflowing to 16 pages" tail of the #103/#104
#    bullet is now historical.
EDITS.append((
    "\u9650\u5236\u53e5\u3002\u5e76\u5165\u524d\u6ce8\u610f\uff1a\u8bba\u6587\u73b0\u4e3a 15 "
    "\u9875\uff0c\u65b0\u589e\u5c0f\u8282\u6709\u6ea2\u51fa\u5230 16 \u9875\u7684\u98ce\u9669\uff0c"
    "\u9700\u914d\u5408\u5220\u51cf\u3002",
    "\u9650\u5236\u53e5\u3002**Pass-39 \u5df2\u5168\u91cf\u5e76\u5165\u5e76\u6ea2\u51fa\u5230 16 "
    "\u9875**\uff08TIFS \u5b9a\u4f4d\u6587\u6863\u6ce8\u660e\u63a5\u53d7 20+ \u9875 measurement "
    "study\uff0c\u6545\u672a\u56de\u538b\uff09\u3002",
))

# 6. Record the #115 / #118 / cleanup outcomes as new bullets, appended right
#    after the #103/#104 bullet.
ANCHOR = (
    "**Pass-39 \u5df2\u5168\u91cf\u5e76\u5165\u5e76\u6ea2\u51fa\u5230 16 "
    "\u9875**\uff08TIFS \u5b9a\u4f4d\u6587\u6863\u6ce8\u660e\u63a5\u53d7 20+ \u9875 measurement "
    "study\uff0c\u6545\u672a\u56de\u538b\uff09\u3002"
)
ADDITION = (
    ANCHOR +
    "\n- **#115 \u5c01\u9762\u4fe1\u91cd\u5199\u5b8c\u6210\uff082026-10-25\uff09**\uff1a"
    "\u65e7\u7a3f\u6570\u5b57\u5168\u8fc7\u671f\uff0813 \u9875 / 190 \u8bcd / 6 \u8868 / 55 \u5f15 / "
    "\u300csecond, independent gateway\u300d\uff09\uff0c\u5df2\u6309 Pass-39 \u5b9e\u6d4b\u91cd\u5199\u4e3a "
    "16 \u9875 / 200 \u8bcd / 7 \u56fe 7 \u8868 / 44 \u5f15\u30013 operator / 15 \u540e\u7aef\uff0c"
    "\u5e76\u8865\u9f50 E7b\u3001E8 \u7ed3\u8bba\u6bb5\u4e0e\u53cc caveat\uff1b"
    "\u540c\u6b65\u81f3 submission_2026-10-21/COVER_LETTER.md\uff08sha256 \u4e00\u81f4\uff09\u3002"
    "\u6821\u9a8c\u811a\u672c experiments/_cover_check.py\uff08\u9010\u6761 claim \u56de\u6eaf\u81f3 "
    "p3_tifs.tex\uff09\u3002\n"
    "- **experiments/window_watch.py\uff082026-10-25\uff0c#118\uff09**\uff1a\u914d\u989d\u7a97\u53e3\u54e8\u5175"
    "\u2014\u2014\u4e00\u6b21\u6027\u63a2\u6d3b\u5168\u90e8\u5df2\u77e5 operator/\u540e\u7aef\uff0c\u8f93\u51fa "
    "results/window_watch_v1.json\uff0c\u628a\u300c\u7b49\u7a97\u53e3\u300d\u7684\u5f85\u8dd1\u9879\u6536\u6210"
    "\u5355\u4e00\u5165\u53e3\u3002\n"
    "- \u8bca\u65ad\u4ef6\u5df2\u5f52\u6863\uff1aresults/ \u4e0b 10 \u4e2a _e*.txt \u79fb\u5165 "
    "results/_scratch/\uff08\u4e0d\u5220\u9664\uff09\uff1brun log \u4fdd\u7559\u5728 results/ \u9876\u5c42\u3002\n"
    "- **\u672a\u6267\u884c\u7684\u52a8\u4f5c**\uff1a\u672c\u8f6e\u4ec5\u6253\u5305\uff0c\u5c1a\u672a\u5411 "
    "TIFS \u63d0\u4ea4\uff1b\u5907\u9009\u671f\u520a\uff08Computers & Security\uff09\u53ea\u5728\u5b9a\u4f4d"
    "\u6587\u6863\u91cc\u5360\u4f4d\uff0c\u65e0\u6539\u5199\u7a3f\u3002"
)
EDITS.append((ANCHOR, ADDITION))


def main() -> int:
    raw = open(P, "rb").read().decode("utf-8")

    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        # Simulate the sequential application: edit 6 anchors on text that
        # only edit 5 creates, so report counts after each prior edit.
        sim = raw
        ok = True
        for i, (old, new) in enumerate(EDITS, 1):
            n = sim.count(old)
            print("%d  count=%d  %r" % (i, n, old[:70]))
            if n != 1:
                ok = False
            else:
                sim = sim.replace(old, new)
        print("all-unique:", ok)
        return 0 if ok else 2

    for old, new in EDITS:
        n = raw.count(old)
        if n != 1:
            print("ABORT: count=%d for anchor: %r" % (n, old[:90]))
            return 1
        raw = raw.replace(old, new)
    print("all %d edits matched exactly once" % len(EDITS))
    open(P, "wb").write(raw.encode("utf-8"))
    print("wrote %d chars (%d -> %d)" % (
        len(raw),
        len(open(P, "rb").read().decode("utf-8")),
        len(raw),
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
