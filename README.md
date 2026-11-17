# 对外跳板机爆破后横向移动检测

一台对外提供 SSH 的跳板机，白天有持续的扫描和爆破噪声，凌晨出现一次成功登录并迅速连到数据库主机。

```
logs/auth.log   949 行（合成，含 3 起真实事件）
labels.json     3 个标注事件
detector/detector.py  基线检测器
tests/          骨架测试
```

## Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
```

## 基线状态

`detector/detector.py` 对每条失败登录和每个请求各产出一条告警，不做任何关联：
不看失败之后有没有成功登录，不看同账号是否跨主机，也不看请求路径是否敏感。

## 标注事件

| kind | 说明 |
|---|---|
| `brute_force_success` | 暴力破解后成功登录 |
| `lateral_movement` | 同一凭据跨主机横向移动 |
| `web_scan` | 敏感路径扫描 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
