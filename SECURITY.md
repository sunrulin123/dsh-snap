# Security Policy / 安全策略

## Supported versions / 支持的版本

| Version | Supported |
| --- | --- |
| 0.7.x | ✅ |

## Reporting a vulnerability / 报告漏洞

**Please do not open a public GitHub issue for security problems.**
**安全问题请不要公开发 issue。**

dsh-snap sits on a trust boundary: it rewrites plugin manifests and restores
`node_modules` on your machine. A bug here can amplify damage instead of
preventing it, so we treat security reports with priority.

Use GitHub [Private vulnerability reporting](../../security/advisories/new)
(Repository → Security → Report a vulnerability), or contact the maintainer
via a private channel listed on the GitHub profile.

请使用 GitHub 的「私密漏洞报告」（仓库 → Security → Report a vulnerability），
或通过维护者 GitHub 主页列出的私密渠道联系。

Include: affected version, a minimal reproduction (scripts/fixtures welcome,
run against a **temp directory**, never a real profile), and the observed vs
expected behavior. 请附：影响版本、最小复现（脚本/夹具请只操作系统临时目录）、
观察到的行为与预期行为。

## Scope / 范围

In scope: anything that lets a crafted snapshot/manifest/journal escape the
store directory, execute code, or destroy live data outside the documented
restore semantics; credential leakage into the store; the rescue web server
(`serve`) accepting non-loopback connections.

属于范围：构造的快照/清单/journal 能够越界写出、执行代码、或在文档声明语义
之外破坏实机数据；凭据进入快照库；救援网页（`serve`）接受非回环连接。

Out of scope: a malicious *local* process tampering with the store while the
user is not looking (the store is user-owned), and social engineering.

不属于范围：本机恶意进程在用户不知情时篡改快照库（快照库属用户所有）、
社会工程学。

## Hardening notes / 加固说明

Two independent audits (37 findings, including 3 P0 trust-boundary issues)
have been fixed; their reproductions are pinned as regression tests in the
selftest suite (`npm test`). If you find a way to bypass one of those gates
(manifest allowlist, junction-ancestor refusal, incremental pollution
detection, restore mutex), that is exactly what we want to hear about.

两轮独立审计的 37 项发现（含 3 个 P0 信任边界问题）已全部修复，复现脚本
固化为回归测试（`npm test`）。如果你找到绕过这些闸门的方法（manifest 白名单、
junction 祖先拒绝、增量污染检测、还原互斥锁），正是我们最想听到的。
