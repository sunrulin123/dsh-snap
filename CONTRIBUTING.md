# Contributing to dsh-snap / 参与贡献

感谢关注 dsh-snap。这是一个社区非官方项目，欢迎任何形式的贡献：bug 报告、文档改进、代码 PR。

## How to report a bug / 如何报 bug

1. 先搜一遍 [现有 issues](../../issues)，避免重复。
2. 用 `.github/ISSUE_TEMPLATE/bug_report.md`（或空 issue）提供：
   - dsh-snap 版本（`node <store>/cli/dsh-snap.mjs state` 或 store 里 `kernel-version.json`）
   - DSH 版本、操作系统
   - 复现步骤 + 期望行为 + 实际行为
   - 相关输出（`doctor` / `crash` / journal 片段）。**贴日志前检查其中是否含 API key 等敏感信息。**
3. 崩溃类问题附上 `crash --hours 48` 的输出最有帮助。

## How to propose a feature / 如何提功能

dsh-snap 的设计哲学是**克制**：危险项只报告不动手、还原必须可撤销、不碰会话与工作区。
提议功能时请说明它与这条线的相容性。先开 issue 讨论再动手写码，避免做完发现方向不合。

## Development / 开发

```bash
git clone https://github.com/sunrulin123/dsh-snap.git
cd dsh-snap
npm test        # 三套件：内核 selftest + 宿主冒烟 + 社区故障注入（全零依赖）
npm run check   # 语法检查
```

- 内核是单文件 ESM `cli/dsh-snap.mjs`（零运行时依赖）；宿主半 `index.js`（Cordis 插件）；Web 面板 `client/index.js`。
- 所有测试零依赖，Node ≥ 20 即可跑，不依赖本机装了 DSH。
- **新增防线必须配"防线失效会红"的负面对照测试**（本项目从审计中沉淀的核心纪律：正向测试全绿 ≠ 防线活着）。

## Pull request guidelines / PR 约定

- 一个 PR 一件事；大改动先开 issue 对齐。
- 保持"危险项只报告不动手"语义：任何新增写操作要有 guard 备份且 fail-closed。
- `npm test` 全绿后再提交；如改动涉及还原/快照语义，请说明你用什么场景验证过。
- 提交信息用祈使句（`fix: ...` / `feat: ...` / `docs: ...`）。

## Security issues / 安全问题

**不要**用公开 issue 报告安全漏洞 — 见 [SECURITY.md](SECURITY.md)。

## License

提交即表示你同意以 [MIT](LICENSE) 许可发布你的贡献。
