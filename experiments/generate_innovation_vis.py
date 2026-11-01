"""
攻击技术创新综合可视化仪表板
读取 9 个方向的实验结果 JSON，生成 ECharts HTML 仪表板
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
OUTPUT = HERE.parent / "reports" / "attack_innovation_dashboard.html"

# 方向定义：显示名、JSON 文件、分组统计键、子类别键、延迟键
DIRECTIONS = [
    {"id": "baseline",  "name": "基线(大规模)",   "file": "large_scale_attack_experiment_v1.json",     "group_key": "by_vector", "latency_key": "avg_latency_ms"},
    {"id": "d1_rl",     "name": "1.自适应RL",      "file": "adaptive_rl_attack_experiment_v1.json",      "group_key": "by_vector", "latency_key": "avg_latency_ms"},
    {"id": "d2_mm",     "name": "2.多模态融合",    "file": "multimodal_attack_experiment_v1.json",      "group_key": "by_vector", "latency_key": "avg_latency_ms"},
    {"id": "d3_llm",    "name": "3.LLM原生",      "file": "llm_native_attack_experiment_v1.json",       "group_key": "by_vector", "latency_key": "avg_latency_ms"},
    {"id": "d4_dist",   "name": "4.分布式/联邦",   "file": "distributed_federated_attack_experiment_v1.json", "group_key": "by_type", "latency_key": "avg_latency_ms"},
    {"id": "d5_zkp",    "name": "5.零知识/隐私",   "file": "zkp_privacy_attack_experiment_v1.json",     "group_key": "by_type",   "latency_key": "avg_latency_ms"},
    {"id": "d6_expl",   "name": "6.可解释性",      "file": "explainability_attack_experiment_v1.json",  "group_key": "by_type",   "latency_key": "avg_latency_ms"},
    {"id": "d7_phys",   "name": "7.物理-链路",     "file": "physical_link_attack_experiment_v1.json",   "group_key": "by_type",   "latency_key": "avg_latency_ms"},
    {"id": "d8_data",   "name": "8.数据投毒",      "file": "data_poisoning_attack_experiment_v1.json",  "group_key": "by_type",   "latency_key": "avg_latency_ms"},
    {"id": "d9_proto",  "name": "9.协议层",        "file": "protocol_attack_experiment_v1.json",        "group_key": "by_type",   "latency_key": "avg_latency_ms"},
    {"id": "d10_prompt", "name": "10.提示词进化",   "file": "phase34_prompt_evolution_attack_v1.json",   "group_key": "by_payload", "latency_key": "avg_latency_ms"},
    {"id": "d11_vecdb",  "name": "11.向量数据库",   "file": "phase35_vector_db_attack_v1.json",          "group_key": "by_type",   "latency_key": "avg_latency_ms"},
    {"id": "d12_orm",    "name": "12.ORM重写链",    "file": "phase36_orm_rewrite_attack_v1.json",        "group_key": "by_type",   "latency_key": "avg_latency_ms"},
    {"id": "d13_shadow", "name": "13.影子数据库",   "file": "phase37_shadow_database_attack_v1.json",    "group_key": "by_phase",  "latency_key": "avg_latency_ms"},
    {"id": "d14_causal", "name": "14.因果推断",     "file": "phase38_causal_inference_attack_v1.json",   "group_key": "by_technique", "latency_key": "avg_latency_ms"},
    {"id": "d15_finger", "name": "15.指纹去匿名化", "file": "phase39_contrastive_fingerprint_attack_v1.json", "group_key": "by_technique", "latency_key": "avg_latency_ms"},
    {"id": "d16_fed",    "name": "16.联邦跨库推断", "file": "phase40_federated_cross_db_attack_v1.json", "group_key": "by_technique", "latency_key": "avg_latency_ms"},
    {"id": "d17_xfer",   "name": "17.Schema迁移",   "file": "phase41_adversarial_schema_transfer_v1.json", "group_key": "by_strategy", "latency_key": "avg_latency_ms"},
    {"id": "d18_gan",    "name": "18.GAN对抗库",    "file": "phase42_gan_adversarial_db_v1.json",        "group_key": "by_strategy", "latency_key": "avg_latency_ms"},
    {"id": "d19_mem",    "name": "19.记忆提取",     "file": "phase43_llm_memory_extraction_v1.json",     "group_key": "by_technique","latency_key": "avg_latency_ms"},
    {"id": "d20_coevo",  "name": "20.攻防共进化",   "file": "phase44_attack_defense_co_evolution_v1.json","group_key": "by_attack_action", "latency_key": "avg_latency_ms"},
]

def load_results():
    loaded = []
    for d in DIRECTIONS:
        path = RESULTS / d["file"]
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        loaded.append({"def": d, "data": data})
    return loaded

def extract_subcategory_stats(entry):
    """提取子类别成功率"""
    d = entry["def"]
    data = entry["data"]
    group = data.get(d["group_key"], {})
    items = []
    for name, stats in group.items():
        total = stats.get("total", 0)
        succ = stats.get("successful", 0)
        rate = succ / total if total > 0 else 0
        items.append({"name": name, "rate": rate, "total": total, "successful": succ})
    items.sort(key=lambda x: x["rate"], reverse=True)
    return items

def main():
    loaded = load_results()
    print(f"加载了 {len(loaded)} 个方向的结果")

    # ============ 构建总览数据 ============
    overview = []
    for entry in loaded:
        s = entry["data"].get("summary", {})
        overview.append({
            "name": entry["def"]["name"],
            "success_rate": s.get("success_rate", 0),
            "latency": s.get("avg_latency_ms", 0),
            "total": s.get("total_probes", 0),
            "successful": s.get("successful_probes", 0),
        })

    # ============ 构建子类别数据（每方向 TOP 子类别） ============
    subcats = {}
    for entry in loaded:
        subcats[entry["def"]["id"]] = extract_subcategory_stats(entry)

    # ============ 构建雷达图数据（归一化 0-100） ============
    max_latency = max([o["latency"] for o in overview if o["latency"] > 0] + [1])
    radar_indicators = [
        {"name": "攻击成功率", "max": 100},
        {"name": "低延迟(反比)", "max": 100},
        {"name": "探针规模", "max": 100},
        {"name": "子类别覆盖", "max": 100},
        {"name": "多引擎覆盖", "max": 100},
    ]
    max_total = max([o["total"] for o in overview] + [1])
    max_subcats = max([len(v) for v in subcats.values()] + [1])
    radar_series = []
    for entry in loaded:
        s = entry["data"].get("summary", {})
        sr = s.get("success_rate", 0) * 100
        latency = s.get("avg_latency_ms", 0)
        low_latency_score = max(0, 100 - (latency / max_latency) * 100)
        total_score = s.get("total_probes", 0) / max_total * 100
        subcat_score = len(subcats[entry["def"]["id"]]) / max_subcats * 100
        engine_score = min(100, s.get("engine_count", s.get("target_count", s.get("db_count", 0))) / 5 * 100)
        radar_series.append({
            "name": entry["def"]["name"],
            "value": [round(sr, 1), round(low_latency_score, 1), round(total_score, 1),
                      round(subcat_score, 1), round(engine_score, 1)],
        })

    # ============ 构建热力图数据（方向 × 成功率区间） ============
    heatmap_x = [o["name"] for o in overview]
    heatmap_y = ["<25%", "25-40%", "40-55%", "55-75%", ">75%"]
    heatmap_data = []
    for xi, entry in enumerate(loaded):
        sr = entry["data"].get("summary", {}).get("success_rate", 0)
        if sr < 0.25: yi = 0
        elif sr < 0.40: yi = 1
        elif sr < 0.55: yi = 2
        elif sr < 0.75: yi = 3
        else: yi = 4
        heatmap_data.append([xi, yi, round(sr * 100, 1)])

    # ============ 生成 HTML ============
    html_template = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>攻击技术创新综合仪表板</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<style>
  body { font-family: "Microsoft YaHei", sans-serif; background: #f5f7fa; margin: 0; padding: 20px; }
  .header { background: linear-gradient(135deg, #1a237e, #283593); color: white; padding: 24px 32px; border-radius: 12px; margin-bottom: 20px; }
  .header h1 { margin: 0 0 8px 0; font-size: 26px; }
  .header p { margin: 0; opacity: 0.85; font-size: 14px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 20px; }
  .card { background: white; border-radius: 10px; padding: 16px 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .card .label { font-size: 12px; color: #666; margin-bottom: 6px; }
  .card .value { font-size: 26px; font-weight: bold; color: #1a237e; }
  .card .sub { font-size: 11px; color: #999; margin-top: 4px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  .panel { background: white; border-radius: 10px; padding: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .panel h3 { margin: 0 0 10px 0; font-size: 15px; color: #333; border-left: 4px solid #283593; padding-left: 8px; }
  .chart { width: 100%; height: 360px; }
  .full { grid-column: 1 / -1; }
  .table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .table th { background: #e8eaf6; padding: 8px; text-align: left; }
  .table td { padding: 8px; border-bottom: 1px solid #eee; }
  .bar-track { background: #e8eaf6; border-radius: 4px; height: 14px; position: relative; }
  .bar-fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg, #3949ab, #e53935); }
  .footer { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ LLM 数据库攻击技术创新综合仪表板</h1>
  <p>20 大攻击技术创新方向 · 每方向 1000+ 探针 · 总计 20,000+ 攻击探针 · 生成时间：__GENTIME__</p>
</div>

<div class="cards" id="cards"></div>

<div class="grid">
  <div class="panel"><h3>📊 各方向攻击成功率对比</h3><div id="chart_overview" class="chart"></div></div>
  <div class="panel"><h3>🎯 五维能力雷达图</h3><div id="chart_radar" class="chart"></div></div>
  <div class="panel full"><h3>🔥 成功率区间分布热力图</h3><div id="chart_heatmap" class="chart" style="height:300px"></div></div>
  <div class="panel"><h3>🏆 各方向 TOP 子类别攻击向量</h3><div id="chart_top" class="chart"></div></div>
  <div class="panel"><h3>⏱️ 成功率 vs 平均延迟 散点图</h3><div id="chart_scatter" class="chart"></div></div>
  <div class="panel full"><h3>📋 全部方向详细数据表</h3><div id="table_area"></div></div>
</div>

<div class="footer">LLM-Attack-Eval Project · 攻击技术创新实验 · 数据来源：results/*.json</div>

<script>
const OVERVIEW = __OVERVIEW_JSON__;
const RADAR_SERIES = __RADAR_JSON__;
const RADAR_INDICATORS = __RADAR_IND_JSON__;
const HEATMAP = __HEATMAP_JSON__;
const HEATMAP_X = __HEATMAP_X_JSON__;
const HEATMAP_Y = __HEATMAP_Y_JSON__;
const SUBCATS = __SUBCATS_JSON__;

// ---- 卡片 ----
const totalProbes = OVERVIEW.reduce((a,b)=>a+b.total,0);
const totalSucc = OVERVIEW.reduce((a,b)=>a+b.successful,0);
const avgSR = totalSucc/totalProbes*100;
const bestDir = OVERVIEW.slice().sort((a,b)=>b.success_rate-a.success_rate)[0];
const cardsHtml = `
  <div class="card"><div class="label">总探针数</div><div class="value">${totalProbes.toLocaleString()}</div><div class="sub">${OVERVIEW.length} 组实验（含基线）</div></div>
  <div class="card"><div class="label">总成功攻击</div><div class="value">${totalSucc.toLocaleString()}</div><div class="sub">跨全部攻击方向</div></div>
  <div class="card"><div class="label">平均成功率</div><div class="value">${avgSR.toFixed(1)}%</div><div class="sub">加权统计</div></div>
  <div class="card"><div class="label">最高成功率方向</div><div class="value" style="font-size:18px">${bestDir.name}</div><div class="sub">${(bestDir.success_rate*100).toFixed(1)}% · ${bestDir.successful} 次成功</div></div>
  <div class="card"><div class="label">攻击方向数</div><div class="value">${OVERVIEW.length - 1} + 1</div><div class="sub">创新方向 + 基线</div></div>
`;
document.getElementById('cards').innerHTML = cardsHtml;

// ---- 总览柱状图 ----
(function(){
  const chart = echarts.init(document.getElementById('chart_overview'));
  const sorted = OVERVIEW.slice().sort((a,b)=>a.success_rate-b.success_rate);
  chart.setOption({
    tooltip: { trigger: 'axis', axisPointer: {type:'shadow'},
      formatter: p => { const d = sorted[p[0].dataIndex];
        return `${d.name}<br/>成功率: <b>${(d.success_rate*100).toFixed(1)}%</b><br/>成功: ${d.successful} / ${d.total}<br/>平均延迟: ${d.latency ? d.latency.toFixed(0)+' ms' : 'N/A'}`; } },
    grid: { left: 110, right: 60, top: 20, bottom: 30 },
    xAxis: { type: 'value', axisLabel: { formatter: v => (v*100).toFixed(0)+'%' } },
    yAxis: { type: 'category', data: sorted.map(d=>d.name), axisLabel: { fontSize: 12 } },
    series: [{ type: 'bar', data: sorted.map(d=>({ value: d.success_rate,
        itemStyle: { color: d.success_rate >= 0.5 ? '#e53935' : (d.success_rate >= 0.35 ? '#fb8c00' : '#1e88e5') } })),
      barWidth: 16,
      label: { show: true, position: 'right', formatter: p => (p.value*100).toFixed(1)+'%', fontSize: 11 } }]
  });
  window.addEventListener('resize', ()=>chart.resize());
})();

// ---- 雷达图 ----
(function(){
  const chart = echarts.init(document.getElementById('chart_radar'));
  const colors = ['#5c6bc0','#26a69a','#ef5350','#ffa726','#66bb6a','#ab47bc','#42a5f5','#8d6e63','#78909c','#ec407a'];
  chart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, textStyle: { fontSize: 11 }, type: 'scroll' },
    radar: { indicator: RADAR_INDICATORS, radius: '62%', center: ['50%','46%'],
      axisName: { color: '#444', fontSize: 12 } },
    series: [{ type: 'radar',
      data: RADAR_SERIES.map((s,i)=>({ name: s.name, value: s.value,
        lineStyle: { color: colors[i%colors.length], width: 1.5 },
        itemStyle: { color: colors[i%colors.length] },
        areaStyle: { color: colors[i%colors.length], opacity: 0.08 } })) }]
  });
  window.addEventListener('resize', ()=>chart.resize());
})();

// ---- 热力图 ----
(function(){
  const chart = echarts.init(document.getElementById('chart_heatmap'));
  const vals = HEATMAP.map(d=>d[2]);
  chart.setOption({
    tooltip: { position: 'top', formatter: p => `${HEATMAP_X[p.value[0]]}<br/>区间: ${HEATMAP_Y[p.value[1]]}<br/>成功率: <b>${p.value[2]}%</b>` },
    grid: { left: 130, right: 60, top: 20, bottom: 60 },
    xAxis: { type: 'category', data: HEATMAP_X, splitArea: { show: true }, axisLabel: { rotate: 30, fontSize: 11 } },
    yAxis: { type: 'category', data: HEATMAP_Y, splitArea: { show: true } },
    visualMap: { min: Math.min(...vals), max: Math.max(...vals), calculable: true, orient: 'horizontal',
      left: 'center', bottom: 0, inRange: { color: ['#e3f2fd','#1565c0','#e53935'] }, textStyle:{fontSize:11} },
    series: [{ type: 'heatmap', data: HEATMAP,
      label: { show: true, formatter: p => p.value[2]+'%', fontSize: 11, color: '#000' },
      itemStyle: { borderColor: '#fff', borderWidth: 2 } }]
  });
  window.addEventListener('resize', ()=>chart.resize());
})();

// ---- TOP 子类别（横向堆叠条形） ----
(function(){
  const chart = echarts.init(document.getElementById('chart_top'));
  const dirNames = []; const seriesData = [];
  Object.keys(SUBCATS).forEach((key, idx) => {
    const list = SUBCATS[key];
    if (list.length === 0) return;
    const top = list[0];
    dirNames.push(key + ' | ' + top.name);
    seriesData.push({ value: top.rate, total: top.total, successful: top.successful,
      itemStyle: { color: ['#5c6bc0','#26a69a','#ef5350','#ffa726','#66bb6a','#ab47bc','#42a5f5','#8d6e63','#78909c'][idx%9] } });
  });
  chart.setOption({
    tooltip: { trigger: 'axis', axisPointer:{type:'shadow'},
      formatter: p => { const d = seriesData[p[0].dataIndex];
        return `${dirNames[p[0].dataIndex]}<br/>成功率: <b>${(d.value*100).toFixed(1)}%</b><br/>成功: ${d.successful} / ${d.total}`; } },
    grid: { left: 10, right: 70, top: 10, bottom: 10, containLabel: true },
    xAxis: { type: 'value', axisLabel: { formatter: v => (v*100).toFixed(0)+'%' } },
    yAxis: { type: 'category', data: dirNames, axisLabel: { fontSize: 10 } },
    series: [{ type: 'bar', data: seriesData, barWidth: 14,
      label: { show: true, position: 'right', formatter: p => (p.value*100).toFixed(1)+'%', fontSize: 10 } }]
  });
  window.addEventListener('resize', ()=>chart.resize());
})();

// ---- 散点图 ----
(function(){
  const chart = echarts.init(document.getElementById('chart_scatter'));
  chart.setOption({
    tooltip: { trigger: 'item', formatter: p => `${p.data[2]}<br/>成功率: <b>${(p.data[0]*100).toFixed(1)}%</b><br/>平均延迟: ${p.data[1].toFixed(0)} ms` },
    grid: { left: 60, right: 40, top: 30, bottom: 50 },
    xAxis: { type: 'value', name: '平均延迟 (ms)', nameLocation: 'middle', nameGap: 28, min: 0 },
    yAxis: { type: 'value', name: '成功率', nameLocation: 'middle', nameGap: 36,
      axisLabel: { formatter: v => (v*100).toFixed(0)+'%' } },
    series: [{ type: 'scatter', symbolSize: 22,
      data: OVERVIEW.filter(d=>d.latency>0).map(d=>({ value: [d.success_rate, d.latency, d.name],
        itemStyle: { color: d.success_rate>=0.4?'#e53935':(d.success_rate>=0.3?'#fb8c00':'#1e88e5'), opacity: 0.85 } })),
      label: { show: true, formatter: p => p.data[2], position: 'top', fontSize: 10 } }]
  });
  window.addEventListener('resize', ()=>chart.resize());
})();

// ---- 数据表 ----
(function(){
  const rows = OVERVIEW.slice().sort((a,b)=>b.success_rate-a.success_rate).map(d=>{
    const w = (d.success_rate*100).toFixed(1);
    return `<tr><td><b>${d.name}</b></td><td>${d.total.toLocaleString()}</td><td>${d.successful.toLocaleString()}</td>
      <td>${d.latency ? d.latency.toFixed(1)+' ms' : 'N/A'}</td>
      <td><div class="bar-track"><div class="bar-fill" style="width:${w}%"></div></div></td>
      <td><b>${w}%</b></td></tr>`;
  }).join('');
  document.getElementById('table_area').innerHTML =
    `<table class="table"><tr><th>攻击方向</th><th>探针数</th><th>成功数</th><th>平均延迟</th><th>成功率分布</th><th>成功率</th></tr>${rows}</table>`;
})();
</script>
</body>
</html>"""

    from datetime import datetime
    html = html_template.replace("__GENTIME__", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("__OVERVIEW_JSON__", json.dumps(overview, ensure_ascii=False))
    html = html.replace("__RADAR_JSON__", json.dumps(radar_series, ensure_ascii=False))
    html = html.replace("__RADAR_IND_JSON__", json.dumps(radar_indicators, ensure_ascii=False))
    html = html.replace("__HEATMAP_JSON__", json.dumps(heatmap_data, ensure_ascii=False))
    html = html.replace("__HEATMAP_X_JSON__", json.dumps(heatmap_x, ensure_ascii=False))
    html = html.replace("__HEATMAP_Y_JSON__", json.dumps(heatmap_y, ensure_ascii=False))
    html = html.replace("__SUBCATS_JSON__", json.dumps(subcats, ensure_ascii=False))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"仪表板已生成: {OUTPUT}")

    # 打印总览摘要
    print("\n===== 总览 =====")
    for o in sorted(overview, key=lambda x: x["success_rate"], reverse=True):
        print(f"  {o['name']}: {o['success_rate']*100:.1f}% ({o['successful']}/{o['total']}) 延迟={o['latency']:.1f}ms")

if __name__ == "__main__":
    main()
