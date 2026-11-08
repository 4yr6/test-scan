# AI API Key 泄漏监控器

24/7 扫描泄漏的AI API key，并用智力测试验证有效性。

## 功能

- **自动扫描**：GitHub、Pastebin 等公开渠道的API key泄露
- **智能识别**：支持 OpenAI、Anthropic、Google、Azure OpenAI 等key格式
- **智力测试**：用预设问题测试key是否真的能回答问题
- **24/7监控**：可配置扫描间隔持续运行
- **结果记录**：JSON格式保存，带时间戳

## 安装

```bash
pip install -r requirements.txt
```

## 使用

### 单次扫描
```bash
python api_key_monitor.py --once
```

### 24/7监控（每6小时扫描一次）
```bash
python api_key_monitor.py --interval 6
```

### 自定义间隔
```bash
python api_key_monitor.py --interval 12
```

## 智力测试题库

内置5道跨领域问题：
- 量子纠缠（物理）
- 递归函数（编程）
- Transformer训练（机器学习）
- Python装饰器（编程）
- 区块链共识机制（加密货币）

Key有效且能回答≥50%题目即算"通过"。

## 输出示例

```
results_20261108_221700.json
├── valid_keys: [...]     # 有效key及测试结果
├── invalid_keys: [...]   # 无效key
└── details: [...]        # 详细结果（含智力测试答案）
```

## 注意

- 本项目仅用于**安全研究**，请勿用于非法用途
- GitHub扫描需配置PAT（见`.env.example`）
- Pastebin扫描使用公开API，无需token
