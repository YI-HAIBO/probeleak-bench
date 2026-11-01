import io, os
p = r'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
with io.open(p, 'rb') as f:
    data = f.read()

old = (
    b"\\bibitem{leaky2025}\r\n"
    b"T.~Green, M.~Gubri, H.~Puerto, S.~Yun, and S.~J. Oh, ``Leaky thoughts: Large\r\n"
    b"reasoning models are not private thinkers,'' \\emph{arXiv preprint\r\n"
    b"arXiv:2506.15674}, 2025; to appear at EMNLP 2025.\r\n"
)

new = (
    b"\\bibitem{leaky2025}\r\n"
    b"T.~Green, M.~Gubri, H.~Puerto, S.~Yun, and S.~J. Oh, ``Leaky thoughts: Large\r\n"
    b"reasoning models are not private thinkers,'' in \\emph{Proc. of the 2025\r\n"
    b"Conference on Empirical Methods in Natural Language Processing (EMNLP)},\r\n"
    b"pp.~26507--26529, 2025. DOI: 10.18653/v1/2025.emnlp-main.1347.\r\n"
)

n = data.count(old)
assert n == 1, f"anchor count = {n}"
data = data.replace(old, new, 1)

tmp = p + '.tmp'
with io.open(tmp, 'wb') as f:
    f.write(data)
os.replace(tmp, p)
print("C2 applied. leaky2025 now a formal EMNLP 2025 proceedings entry.")
