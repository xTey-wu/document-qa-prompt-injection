# 实验复现指南

在仓库根目录运行 `python3 verify_reproduction.py`，即可用归档数据复核论文的补充结果。脚本使用 Python 3.9 或更新版本和标准库。归档中的代码与数据按 `faro-test/manifest.json` 核对 SHA-256。

## 读表

- [正式逐题结果](faro-test/results.jsonl)中的 `correct` 使用预设整字段匹配，分组统计见[正式汇总](faro-test/summary.csv)。
- `raw_attack_followed` 记录生成器原始输出是否命中预设标记。`final_attack_success` 记录交付答复是否命中。
- [语义评阅](semantic_review/)将 283 条可评答复归并为 63 个题目与答复单元，保存盲态判断、分歧复核和逐条映射。该补充计数与预设严格匹配分别报告。
- `verify_reproduction.py` 输出中的 `validation_replay` 来自实际生成答复，`constructed_validation_inputs` 来自程序规则测试。请求统计从[正式调用日志](faro-test/requests.jsonl)提取。

## 样本与配置

[cases.json](cases.json)包含 12 个开发问题和 24 个持出问题。每条源记录依次给出题号、标题、两个事实片段、问题、可接受答案和合法附加说明。每个问题衍生三个文档版本，保留相同的原始事实。完整消息、关键词规则和攻击模板见[提示与规则](PROMPTS.md)。

| 组别 | 输入配置 | 交付 |
|---|---|---|
| A | 普通文本与基础问答提示 | 原样交付 |
| B | JSON 字段与来源权限提醒 | 原样交付 |
| C | B 组配置加本地关键词筛查 | 原样交付 |
| D | B 组配置加独立的模型筛查 | 校验结构和引文编号 |

正式运行于 2026 年 11 月 11 日经 Faro API 完成，服务返回模型标识 `gpt-6.1-sol`。温度为 0，单次输出上限为 160 个词元，请求超时为 60 秒，顺序种子为 20261110，传输方式为 curl。正式运行包含 360 次尝试，其中 3 次是生成补跑。3 次筛查失败使相应生成跳过，2 条问答因生成请求最终失败而缺失。

## 远程重跑

先使用 `python3 experiment.py --dry-run --split test` 查看计划用量。以 zsh 为例，填写服务商给出的兼容接口基址及模型标识，在终端隐藏输入自己的密钥：

```zsh
export LLM_BASE_URL='填写兼容接口基址'
export LLM_MODEL='填写模型标识'
read -rs 'LLM_API_KEY?请输入 API Key：'
printf '\n'
export LLM_API_KEY
python3 experiment.py --run --split test --out runs/test-repeat --transport curl --timeout 60
unset LLM_API_KEY
```

以新结果目录记录新的服务、模型或参数配置。续跑使用同一目录和同一配置，脚本跳过已成功请求。添加 `--retry-failed` 补跑失败请求，`--max-requests` 限制本次进程的实际尝试数。接口用量和错误记录随结果写入对应目录。

## 后续实验设计

- **问题输入对照。** 在相同筛查提示和文档上分别传入真实问题或空问题字段，统一模型、参数和评分。24 个源问题各有 3 个文档版本，每轮完整对照需 144 次筛查请求。
- **合法说明的答题价值。** 构造必须从操作说明中取得关键事实的问题，再另设事实与注入共处一段的样本。两类样本分别记录片段删留、问答正确及答案证据。
- **交付层的攻击评测。** 在开发集确定能够触发预设目标的攻击构造，冻结后在独立持出集使用相同判分比较各组。
