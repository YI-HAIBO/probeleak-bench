"""
Attack Visualization Generator - 生成攻击技术可视化图谱
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any

# 配置
HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
CATALOG_PATH = RESULTS / "attack_catalog.json"
EXPERIMENT_PATH = RESULTS / "scale_attack_experiment_v1.json"

def load_data():
    """加载数据"""
    with open(CATALOG_PATH, 'r', encoding='utf-8') as f:
        catalog = json.load(f)

    with open(EXPERIMENT_PATH, 'r', encoding='utf-8') as f:
        experiment = json.load(f)

    return catalog, experiment

def calculate_mean(values):
    """计算平均值"""
    if not values:
        return 0
    return sum(values) / len(values)

def generate_html_visualization(catalog: Dict, experiment: Dict) -> str:
    """生成HTML可视化图谱"""

    # 准备攻击向量数据
    vectors_data = []
    for vector, stats in experiment['by_vector'].items():
        vectors_data.append({
            "id": vector,
            "label": vector,
            "success_rate": stats['successful'] / stats['total'] if stats['total'] > 0 else 0,
            "count": stats['total'],
            "avg_latency": calculate_mean(stats['latencies']) if stats['latencies'] else 0
        })

    # 准备数据库引擎数据
    engines_data = []
    for engine, stats in experiment['by_engine'].items():
        engines_data.append({
            "id": engine,
            "label": engine,
            "success_rate": stats['successful'] / stats['total'] if stats['total'] > 0 else 0,
            "count": stats['total'],
            "avg_latency": calculate_mean(stats['latencies']) if stats['latencies'] else 0
        })

    # 生成图谱 HTML
    vectors_json = json.dumps(vectors_data)
    engines_json = json.dumps(engines_data)

    # 完整HTML模板
    html_content = f"""<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>数据库大模型攻击技术图谱</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .chart-container {{ background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 20px 0; padding: 20px; }}
        .chart-title {{ font-size: 24px; font-weight: bold; color: #333; margin-bottom: 15px; }}
        .legend {{ display: flex; justify-content: center; gap: 20px; margin: 20px 0; }}
        .legend-item {{ display: flex; alignItems: center; gap: 5px; }}
        .legend-color {{ width: 20px; height: 20px; border-radius: 4px; }}
        .legend-success {{ background: #dc3545; }}
        .legend-medium {{ background: #fd7e14; }}
        .legend-low {{ background: #198754; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="chart-title">🎯 数据库大模型攻击技术图谱</div>

        <div class="legend">
            <div class="legend-item">
                <div class="legend-color legend-success"></div>
                <span>成功率高 (≥ 50%)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color legend-medium"></div>
                <span>成功率中 (30%-50%)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color legend-low"></div>
                <span>成功率低 (< 30%)</span>
            </div>
        </div>

        <div class="chart-container">
            <div id="attack_vectors" style="width: 100%; height: 600px;"></div>
        </div>

        <div class="chart-container">
            <div id="database_engines" style="width: 100%; height: 500px;"></div>
        </div>

        <div class="chart-container">
            <div id="associations" style="width: 100%; height: 500px;"></div>
        </div>
    </div>

    <script>
        const vectorsData = {vectors_json};
        const enginesData = {engines_json};

        // 攻击向量网络图谱
        const vectorChart = echarts.init(document.getElementById('attack_vectors'));
        vectorChart.setOption({{
            title: {{
                text: '攻击向量成功率网络图谱',
                left: 'center',
                textStyle: {{ fontSize: 20, fontWeight: 'bold' }}
            }},
            tooltip: {{
                trigger: 'item',
                formatter: function(params) {{
                    return params.data.label + '<br/>成功率：' + (params.data.success_rate * 100).toFixed(1) + '%' + '<br/>成功率等级：' + getSuccessLevel(params.data.success_rate) + '<br/>测试次数：' + params.data.count;
                }}
            }},
            legend: {{
                data: ['攻击向量'],
                bottom: 0
            }},
            series: [{{
                name: '攻击向量',
                type: 'graph',
                layout: 'force',
                data: vectorsData.map(item => ({{
                    ...item,
                    symbolSize: 30 + item.count * 2,
                    itemStyle: {{
                        color: getSuccessColor(item.success_rate)
                    }},
                    label: {{
                        show: true,
                        position: 'right',
                        formatter: function(params) {{ return params.data.id + ' ' + params.data.count; }}
                    }}
                }})),
                links: [
                    {{ from: 'sql_injection', to: 'driver_escaping' }},
                    {{ from: 'sql_injection', to: 'error_oracle' }},
                    {{ from: 'shard_routing', to: 'replication_lag_stale_read' }},
                    {{ from: 'cursor_metadata', to: 'pool_pollution' }},
                    {{ from: 'consistency_level', to: 'node_failure' }}
                ],
                force: {{
                    repulsion: 200,
                    edgeLength: 150,
                    layoutAnimation: true
                }},
                roam: true,
                keepClusterInLevel: true
            }}]
        }});

        // 数据库引擎雷达图
        const engineChart = echarts.init(document.getElementById('database_engines'));
        const axisNames = Array.from(new Set(vectorsData.map(item => item.id)));
        engineChart.setOption({{
            title: {{
                text: '数据库引擎成功率雷达图',
                left: 'center',
                textStyle: {{ fontSize: 20, fontWeight: 'bold' }}
            }},
            radar: {{
                indicator: axisNames.map(name => ({{ name: name, max: 1.0 }}))
            }},
            tooltip: {{}},
            legend: {{ data: ['数据库引擎'] }},
            series: [{{
                name: '数据库引擎',
                type: 'radar',
                data: enginesData.map(engine => ({{
                    value: engine.id === 'postgresql' ?
                        vectorsData.filter(v => v.id === 'sql_injection').map(v => v.success_rate) :
                        vectorsData.map(v => v.success_rate),
                    name: engine.id,
                    itemStyle: {{ color: getEngineColor(engine.id) }}
                }}))
            }}]
        }});

        // 关系网络图
        const assocChart = echarts.init(document.getElementById('associations'));
        const assocData = vectorsData.map(v => ({{ id: v.id, name: v.id, x: Math.random() * 1000, y: Math.random() * 500 }})) +
                          enginesData.map(e => ({{ id: e.id, name: e.id, category: 1, x: Math.random() * 1000 + 500, y: Math.random() * 500 }}));
        const assocLinks = vectorsData.flatMap(v =>
            enginesData.map(e => ({{ from: v.id, to: e.id, value: v.count * e.count / 1000 }}))
        );
        assocChart.setOption({{
            title: {{
                text: '攻击向量与数据库引擎关系网络',
                left: 'center',
                textStyle: {{ fontSize: 20, fontWeight: 'bold' }}
            }},
            tooltip: {{}},
            series: [{{
                type: 'graph',
                layout: 'force',
                data: assocData,
                links: assocLinks,
                force: {{ repulsion: 200, edgeLength: 50 }}
            }}]
        }});

        function getSuccessColor(rate) {{
            return rate >= 0.5 ? '#dc3545' : rate >= 0.3 ? '#fd7e14' : '#198754';
        }}

        function getSuccessLevel(rate) {{
            return rate >= 0.5 ? '高' : rate >= 0.3 ? '中' : '低';
        }}

        function getEngineColor(engine) {{
            const colors = {{
                'postgresql': '#4e79a7',
                'mysql': '#f28e2b',
                'redis': '#e15759',
                'mongodb': '#76b7b2',
                'duckdb': '#59a14f'
            }};
            return colors[engine] || '#8c564b';
        }}

        window.addEventListener('resize', () => {{
            vectorChart.resize();
            engineChart.resize();
            assocChart.resize();
        }});
    </script>
</body>
</html>"""

    return html_content

if __name__ == "__main__":
    print("=" * 70)
    print("Attack Visualization Generator - 生成攻击技术可视化图谱")
    print("=" * 70)

    # 加载数据
    catalog, experiment = load_data()
    print(f"加载完成：{len(catalog['action_types'])} 个原语, {len(experiment['probes'])} 个探针")

    # 生成可视化
    html_content = generate_html_visualization(catalog, experiment)

    # 保存文件
    output_path = RESULTS / "attack_technology_vis.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n可视化图谱已保存到：{output_path}")

    # 打印摘要
    print("\n" + "=" * 70)
    print("图谱包含以下部分：")
    print("1. 攻击向量成功率网络图谱 - 显示攻击向量和它们的成功率")
    print("2. 数据库引擎雷达图 - 显示不同引擎在各向量上的表现")
    print("3. 关系网络图 - 显示攻击向量与引擎之间的关联")
