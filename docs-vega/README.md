# Vega 文档

这里放 **Vega 自有**的文档。上游 sing-box 的文档在仓库根的 `docs/`（那是他们
的 mkdocs 文档树），两者不要混——混进去会被上游的文档构建拾取，也会干扰每次
rebase。

需要的话看根目录 [`README.md`](../README.md) 了解项目本身。

## 索引

| 文档 | 讲什么 | 什么时候看 |
|---|---|---|
| [`BASELINE.md`](BASELINE.md) | 上游基线版本、**改了上游哪些文件**、升级步骤 | 升级 sing-box 之前必看 |
| [`nowhere/CAPABILITIES.md`](nowhere/CAPABILITIES.md) | Nowhere 的 carrier / Egress 能力、配置示例、验收范围 | 配 Nowhere 节点、排查 Nowhere 问题 |
| [`nowhere/UPGRADE-3.3.0.md`](nowhere/UPGRADE-3.3.0.md) | Nowhere-Go 3.3.0 升级记录与互通验证 | 跟 Nowhere 上游对比时 |
| [`audits/2026-11-01.md`](audits/2026-11-01.md) | 自有模块审核与修复记录 | 了解历史决策 |
| [`audits/2026-11-02.md`](audits/2026-11-02.md) | 订阅修复、功能对照、隐私边界 | 同上 |
| [`audits/2026-11-04-fixes.md`](audits/2026-11-04-fixes.md) | 一批 audit 修复的范围与未验证项 | 同上 |

## 运维记录放哪

生产机器的实际操作记录（部署步骤、踩过的坑、实测数据）不在这个仓库里，
在本地维护的 `VEGA-HANDOFF.md`。原因：里面含服务器 IP、密码等敏感信息，
不适合随仓库公开。

## 加新文档的约定

- 能力/设计类 → `docs-vega/` 顶层或对应子目录
- 一次性的事件记录（审核、事故、迁移）→ `docs-vega/audits/YYYY-MM-DD-<主题>.md`
- 别在仓库根新增 `.md`：根目录只留 `README.md`（上游文件也在这里，保持干净）
