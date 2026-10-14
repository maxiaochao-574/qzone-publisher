# qzone-publisher

一个 WorkBuddy / Codex 技能：通过本机运行的 NapCat，向 QQ 空间（Qzone）发布**单张图片 + 文字**说说，并提供可核对的回读检查。

> 这是一个技能（Skill），不是一个 MCP 服务。安装后由 AI 读取流程并执行随包脚本。

## 它能做什么

- `prepare` — 完全离线：校验输入、计算图片 SHA-256 与 `request_digest`、写出 `manifest.json`。**不占用任何发布锁。**
- `publish` — 需四项显式确认后才获取防重复锁并联网，上传图片并发表。
- `verify` — 只读回查：动态 ID、完整正文、图片数量必须恰好为 1。**绝不重发。**

## 不能做什么（v1 限制）

- 仅支持**单图 + 文字**；不支持视频、多图、相册选择。
- **不支持指定私密可见性**，按接口默认可见性处理（实质公开）。需要私密请改用官方客户端。
- 接口为**非官方逆向接口**，可能随时失效或触发风控；遇到验证码请停止，不要绕过。

## 依赖

- Python 3.8+，**仅标准库**。
- 本机运行 **NapCat**，WebUI 已启用，存在 `config/webui.json`。
- 出网仅限 `user.qzone.qq.com` 与 `up.qzone.qq.com` 两个 HTTPS 域名。

## 快速开始

```bash
python scripts/qzone_publisher.py prepare \
  --request request.json --job-dir ./jobs/job001 --state-dir ./state

python scripts/qzone_publisher.py publish \
  --job-dir ./jobs/job001 --state-dir ./state \
  --confirm-publish --confirm-account <QQ号> \
  --confirm-visibility api-default-public-risk \
  --confirm-digest <prepare 输出的摘要>

python scripts/qzone_publisher.py verify --job-dir ./jobs/job001
```

运行测试（需设置 PYTHONPATH 指向 `scripts/`）：

```bash
PYTHONPATH=./scripts python -m unittest discover -s ./tests
```

## 安全设计要点

- 凭据（NapCat token、会话凭据、Qzone cookies、`skey`/`p_skey`/`g_tk`）**仅内存使用**，不写盘、不输出；错误只返回阶段名与白名单类别。
- 网络出口受限：NapCat 仅允许 `127.0.0.1`；外部仅两个固定 HTTPS 域名；忽略环境代理；拒绝重定向。
- 双重防误发：任务级 `O_EXCL` 尝试锁 + 用户级永久指纹锁（账号 + 正文 + 图片哈希），后者仅在 `publish` 确认门之后获取。
- `action_digest` 为内容完整性/预览确认用途，是普通 SHA-256，**不是 HMAC、不是签名**，不用于身份认证。
- 发布结果不明（成功回执但无 `tid`）会保持 `publish_outcome_unknown`，需人工核对，不自动重试。
- `verify` 只读取最近 5 条；找不到 `tid` **不等于**未发布。

## 目录结构

```
SKILL.md                      技能说明（触发词、授权流程、命令）
scripts/qzone_publisher.py    实现（纯标准库）
references/protocol.md        传输、信任边界、g_tk 计算、来源说明
tests/test_qzone_publisher.py 离线测试
```

## 来源与许可

本技能为独立实现。Qzone CGI 字段参考了公开项目 `Zhalslar/astrbot_plugin_qzone`，**未复制其源码**；上游许可未确认，因此本仓库不声称继承任何上游开源许可。

## 免责声明

使用非官方接口存在账号风控风险。请仅在自己的账号上使用，并对发布内容自行负责。
