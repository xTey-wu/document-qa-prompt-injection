# 接口联调记录

两次联调检查模型响应能否通过远程接口返回，正式论文结果使用 [faro-test](../faro-test/)。

| 目录 | 传输方式 | 请求尝试 | 返回响应 | 传输异常 |
|---|---|---:|---:|---:|
| [faro-pilot](faro-pilot/) | Python urllib | 1 | 0 | 1 |
| [faro-curl-pilot](faro-curl-pilot/) | curl | 6 | 1 | 5 |

各目录包含对应运行清单、逐次调用、逐题记录及汇总。[通用评测包](../archives/evaluation-kit.zip)中的脚本对应首次联调指纹，[Faro 联调包](../archives/faro-pilot-kit.zip)中的脚本对应 curl 联调指纹。

连接探测脚本 [probe_faro.py](probe_faro.py) 读取终端环境中的 `LLM_API_KEY`，检查模型列表并发送一条数字问答请求。
