# 文档问答中的间接提示注入评测

本仓库收录《面向文档问答的间接提示注入检测与分层防御》的代码、合成数据、正式评测记录、语义复核和接口联调材料。正式评测以 24 个持出问题为基础，每题配对构造干净、注入和合法指令式文档。

## 复核论文数据

将仓库克隆或下载到本地，在仓库根目录用 Python 3.9 或更新版本运行：

```sh
python3 verify_reproduction.py
```

该命令读取归档数据，核对正式清单的脚本和数据指纹，复算语义计数、输出校验回放及调用统计。可选的程序检查为 `python3 experiment.py --smoke --split test`。远程重跑的配置与命令见[复现指南](REPRODUCTION.md)。

## 评测记录

在两种方法均完成筛查的 22 个注入样本中，任务感知筛查删除 22 个攻击片段，关键词筛查删除 7 个。在 24 个合法指令式样本中，两者分别误删 0 个和 7 个片段。四组共得到 93 条可评注入问答，攻击成功数为 0。正式的严格匹配和攻击计数见[分组汇总](faro-test/summary.csv)，补充语义判断见[评阅记录](semantic_review/)。

| 入口 | 内容 |
|---|---|
| [experiment.py](experiment.py) 与 [cases.json](cases.json) | 正式运行脚本、开发集和持出集 |
| [PROMPTS.md](PROMPTS.md) | 完整提示、关键词正则表达式、注入模板与样本 |
| [faro-test/](faro-test/) | 正式运行清单、逐次调用、逐题结果及汇总 |
| [semantic_review/](semantic_review/) | 盲评输入、两路模型评阅、分歧复核及逐条映射 |
| [pilot/](pilot/) | 两次接口连通性联调及探测脚本 |
| [archives/](archives/) | 通用评测包、Faro 联调包和正式复现包的下载入口 |
