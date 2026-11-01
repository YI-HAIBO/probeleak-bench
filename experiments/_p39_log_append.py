"""Append the closing-round entry to the 2026-10-25 daily log.

Append-only: reads and writes bytes, never rewrites existing content.
"""
import sys

P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\.workbuddy\memory\2026-10-25.md"

BLOCK = """
## 收口轮（2026-10-25 晚间，#115–#118）

- **#115 封面信重写**：`paper/COVER_LETTER.md` 旧稿数字全过期（13 页 / 190 词 /
  6 表 / 55 引 / "second, independent gateway"），已按 Pass-39 实测重写为
  16 页 / 200 词 / 7 图 7 表 / 44 引、3 operator / 15 后端，并补 E7b、E8 结论段
  与 oracle / 词袋余弦两条 caveat；sha256 同步至 submission_2026-10-21。
  `experiments/_cover_check.py` 逐条 claim 回溯 p3_tifs.tex 校验。
- **#117 收尾**：results/ 下 10 个 `_e*.txt` 诊断件移入 `results/_scratch/`
  （不删除，run log 留在顶层）；MEMORY.md 遗留段口径刷新（B2 已补满 40/40、
  Pass-39 已并入、剩余科学缺口明确列出）。顺手修掉一处 Pass-38 尾巴被并入
  Pass-39 行造成的重复串（"：15 页 563,770 B …"）。
- **#118 `experiments/window_watch.py`**：一次性探活 15 后端 / 3 operator，
  10/15 available，无新开放。仍锁：M_Q、M_B（model_id_not_found）、M_R、M_S
  （rate_limited）、N_A（error）。产出 `results/window_watch_v1.json`，把
  「等配额窗口」的待跑项收成单一入口。
- **#116/#117 E9**（`e9_coevo_vs_adaptive_defense.py`）：共进化语料与固定语料
  同时过 D23 / D23' / D30 / D30b（非 oracle 形状规则）/ 堆叠，防御在 R1 后
  按观测泄漏文本重拟合签名类。预检踩掉一个真 bug：`\\b` 锚点抓不住
  `FAKE_wxm_sk-...`（`_` 是 word 字符），必须去掉前后 word boundary 才能
  命中 15/15 把假 key。目标侧 1,200 TPM 限流，一轮约 10 分钟。
"""

def main() -> int:
    raw = open(P, "rb").read().decode("utf-8")
    if "收口轮（2026-10-25 晚间" in raw:
        print("already appended; nothing to do")
        return 0
    add = chr(10) + BLOCK
    if not raw.endswith(chr(10)):
        add = chr(10) + add
    open(P, "wb").write((raw + add).encode("utf-8"))
    print("appended %d chars -> total %d" % (len(add), len(raw + add)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
