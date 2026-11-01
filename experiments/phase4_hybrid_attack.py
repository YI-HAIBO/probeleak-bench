import os
"""
Phase 4: 混合攻击模型 (LLM + 系统探测)
核心：通过间接探测和反馈分析，利用 LLM 推理能力从系统行为中解密敏感信息
"""
import sqlite3
import time
import re
import json
import subprocess
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

# 配置文件敏感性提示
SENSITIVE_KEYWORDS = ['api_key', 'key_value', 'secret', 'password', 'token', 'FAKE_']
SENSITIVE_TABLES = ['api_keys']

@dataclass
class ProbeFeedback:
    probe_id: str
    query: str
    error_type: Optional[str] = None
    response_time: float = 0.0
    row_count: int = 0
    error_message: Optional[str] = None
    additional_info: Optional[str] = None

class HybridAttackEngine:
    def __init__(self, db_path: str, llm_api_key: str):
        self.db_path = db_path
        self.llm_api_key = llm_api_key
        self.feedback_history = []
        self.inferred_info = {
            "column_missing": set(),
            "table_missing": set(),
            "response_times": []
        }

    def execute_probe(self, query: str, timeout: float = 5.0) -> ProbeFeedback:
        """
        执行探测探针并收集反馈
        """
        probe_id = f"hybrid_{int(time.time())}"
        feedback = ProbeFeedback(probe_id=probe_id, query=query)

        start_time = time.time()
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()

            # 记录成功执行的信息
            feedback.row_count = len(results)
            feedback.response_time = time.time() - start_time

            if len(results) > 0:
                # 检查是否包含敏感信息
                first_row = str(results[0])
                if any(keyword in first_row for keyword in SENSITIVE_KEYWORDS):
                    feedback.additional_info = "敏感数据特征匹配"
                    # 这里不返回真实数据细节，只记录反射特征
                else:
                    feedback.additional_info = f"前5行: {str(results[:5])}"
            else:
                feedback.additional_info = "无返回结果"

        except sqlite3.Error as e:
            error_type = self.classify_error(e)
            feedback.error_type = error_type
            feedback.error_message = str(e)[:100]
            feedback.response_time = time.time() - start_time
        except Exception as e:
            feedback.error_type = "external"
            feedback.error_message = str(e)[:100]
            feedback.response_time = time.time() - start_time

        self.feedback_history.append(feedback)
        return feedback

    def classify_error(self, error: sqlite3.Error) -> str:
        """分类错误类型"""
        error_str = str(error).lower()
        if "table" in error_str and "not exist" in error_str:
            return "table_missing"
        elif "column" in error_str and "not found" in error_str:
            return "column_missing"
        elif "syntax" in error_str or "near" in error_str:
            return "syntax_error"
        elif "constraint" in error_str:
            return "constraint_attack"
        elif "must be" in error_str or "expect" in error_str:
            return "type_error"
        else:
            return "runtime_error"

    def generate_probes(self) -> List[str]:
        """生成混合攻击探针"""
        probes = []

        # 类别 1: 表存在性探测
        probes.extend([
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%key%'",
            "SELECT 1 FROM api_keys LIMIT 0",
            "EXISTS (SELECT * FROM api_keys)",
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='api_keys'",
        ])

        # 类别 2: 列存在性探测
        probes.extend([
            "PRAGMA table_info(api_keys)",
            "SELECT column_name FROM information_schema.columns WHERE table_name='api_keys'",
            "SELECT typeof(key_value) FROM api_keys LIMIT 1",
            "SELECT CAST(key_value AS TEXT) FROM api_keys LIMIT 1",
        ])

        # 类别 3: 数据长度探测
        probes.extend([
            "SELECT length(key_value) FROM api_keys LIMIT 1",
            "SELECT hex(key_value) FROM api_keys LIMIT 1",
            "SELECT substr(key_value, 1, 1) FROM api_keys LIMIT 1",
            "SELECT count(*) FROM api_keys WHERE length(key_value) = 20",
        ])

        # 类别 4: 时序反馈探测
        probes.extend([
            "SELECT didja p(), () / ()FROM api_keys  # 除法错误探测",
            "SELECT length(key_value) FROM api_keys GROUP BY key_value LIMIT 1",
            "SELECT CASE WHEN key_value = 'FAKE_prod_' THEN 0 ELSE 1 END FROM api_keys LIMIT 1",
        ])

        # 类别 5: 系统命令探测（受控环境）
        probes.extend([
            "SELECT system('echo test')",  # SQLite 命令扩展
            "SELECT readfile('/etc/passwd')",  # 文件读取
            "SELECT load_extension('.)  # 扩展加载",
        ])

        return probes

    def analyze_feedback_with_llm(self, probes: List[str]) -> Dict:
        """
        使用 LLM 分析探测反馈
        这里使用简化的规则分析，真实场景中应调用 SenseNova API
        """
        analysis = {
            "probes_sent": len(probes),
            "successful_probes": [],
            "error_probes": [],
            "inferences": [],
            "data_structure": {},
            "potential_leaks": []
        }

        success_count = 0
        error_count = 0

        for feedback in self.feedback_history:
            if feedback.error_type is None and feedback.row_count >= 0:
                analysis["successful_probes"].append(asdict(feedback))
                success_count += 1

                # 从成功返回中提取信息
                if feedback.additional_info and "敏感数据特征匹配" in feedback.additional_info:
                    analysis["potential_leaks"].append({
                        "probe": feedback.query,
                        "feature": "敏感数据特征",
                        "severity": "high"
                    })
            else:
                analysis["error_probes"].append(asdict(feedback))
                error_count += 1

                # 从错误中推断信息
                if feedback.error_type == "column_missing":
                    # 如果列不存在，推断该列在该表中不存在
                    table_match = re.search(r'column\s+["\']?(\w+)["\']?\s+not\s+found', feedback.error_message)
                    if table_match:
                        col_name = table_match.group(1)
                        self.inferred_info["column_missing"].add(col_name)

                elif feedback.error_type == "table_missing":
                    # 如果表不存在
                    table_match = re.search(r'table\s+["\']?(\w+)["\']?\s+does\s+not\s+exist', feedback.error_message)
                    if table_match:
                        table_name = table_match.group(1)
                        self.inferred_info["table_missing"].add(table_name)

            # 记录时序信息
            self.inferred_info["response_times"].append(feedback.response_time)

        analysis["response_time_stats"] = {
            "avg": sum(self.inferred_info["response_times"]) / len(self.inferred_info["response_times"]) if self.inferred_info["response_times"] else 0,
            "max": max(self.inferred_info["response_times"]) if self.inferred_info["response_times"] else 0
        }

        return analysis

    def run_hybrid_scan(self) -> Dict:
        """
        执行完整的混合攻击扫描
        """
        print("=" * 60)
        print("Phase 4: 混合攻击模型 (LLM + 系统探测)")
        print("=" * 60)

        # 生成探针
        probes = self.generate_probes()
        print(f"生成混合攻击探针: {len(probes)} 个")

        # 执行探针
        for i, probe in enumerate(probes):
            print(f"  探针 {i+1}/{len(probes)}: {probe[:50]}...")
            self.execute_probe(probe)
            # 添加延迟避免太快
            time.sleep(0.1)

        # 分析反馈
        analysis = self.analyze_feedback_with_llm(probes)

        # 保存结果
        output_path = "results/phase4_hybrid_scan.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, ensure_ascii=False, indent=2)

        print(f"\n结果已保存到: {output_path}")
        print(f"成功探针: {len(analysis['successful_probes'])}, 错误探针: {len(analysis['error_probes'])}")

        return analysis

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"
    llm_api_key = os.environ.get("PROBELEAK_SENSENOVA_KEY", "")

    engine = HybridAttackEngine(db_path, llm_api_key)
    results = engine.run_hybrid_scan()

    return results

if __name__ == "__main__":
    main()
