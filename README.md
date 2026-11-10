# dsh-snap — 装插件搞崩，一键回到装前

**装前自动快照 + 外部一键还原，为 DSH 插件生态补上 checkpoint 能力**

> 每次装/删插件前自动拍快照；插件把 DSH 搞崩后，用一个不依赖 DSH 的外部 CLI 一键回到装前。危险项只报告，绝不动手。

English | [中文](#中文) | [Changelog](CHANGELOG.md) | [Security](SECURITY.md)

> ⚠️ 非官方社区项目 / Unofficial community project — 与 DeepSeek 官方无关，未经官方审核。Not affiliated with or endorsed by DeepSeek.

---

## 中文

### 它解决什么

DSH 插件生态的高频事故：装了一个坏插件 → DSH 起不来/会话全崩/配置被重置 → 没有还原点，只能重装或手搓恢复。官方功能组合（engines.dsh 闸门、安装失败诊断、热更新回退）只覆盖"事后可诊断"，**没有"事前快照 + 外部还原"**。相邻生态（Claude Code / Cursor / OpenCode / VS Code / Home Assistant）"动作前快照+一键回滚"全部是官方内置——dsh-snap 把这个缺口补上。

### 三条触发路径（全覆盖）

| 你怎么装的插件 | dsh-snap 怎么保护你 |
|---|---|
| 让 AI agent 帮你装（plugin_manager 工具） | 工具执行**前**拦截快照（`tools/pre-execute`），带 spec 记录 |
| Web 界面点安装/更新 | pnpm 动 node_modules **之前**快照（`plugin-manager/install-state`） |
| 终端 `dsh plugin add`（独立进程） | 监视 `.plugin-manager/run.json` 尽力快照（应用运行期间 CLI 被官方拒绝操作 desktop profile，故此路径为 best-effort；此场景以最近一次快照为还原点） |
| 手动 | 设置页「立即快照」按钮 / `/snap now` 命令 / CLI `snapshot` |

### 安装

```bash
# 方式一：npm（推荐）
dsh plugin --profile desktop add dsh-snap     # 或在 Web 插件页搜索 dsh-snap
# 方式二：从源码安装
git clone https://github.com/sunrulin123/dsh-snap.git
cd dsh-snap && npm pack
pnpm add ./dsh-snap-x.y.z.tgz   # 然后把 "dsh-snap" 加进 profile 的 dsh.profile.bundles
```

装完即生效：启动时后台拍一次基线快照（不阻塞启动），之后每次装/删插件自动快照。

### 还原（三种姿势，DSH 死了也能跑）

快照库在 `$DSH_HOME/../.dsh-snap/`（与 profile 同卷、DSH 目录之外，环境变量 `DSH_SNAP_HOME` 可覆盖）。里面常驻一份零依赖 CLI 副本：

```bash
# 1. 完全退出 DSH（托盘也退出）
# 2. 任意一种：
node "<快照库>/cli/dsh-snap.mjs" restore last     # 回到最近一次装前
node "<快照库>/cli/dsh-snap.mjs" list             # 看所有快照
<快照库>/cli/restore-last.bat                      # 双击营救（Windows）
# 3. 撤销刚才的还原（还原前自动拍 guard 快照）
node "<快照库>/cli/dsh-snap.mjs" undo
```

**还原语义（克制哲学）**：

- ✅ 回写 profile 清单（package.json / pnpm-lock.yaml / cordis.patch.yml / compatibility.json / pnpm-workspace.yaml）
- ✅ 回填 node_modules 中缺失/被改坏的文件（硬链接，秒级）
- ✅ 还原前自动拍 guard 快照 —— **还原本身可撤销**
- ⏸ 多出来的包默认保留并报告（`--prune-extraneous` 才移入 trash，改名不删除）
- ⏸ `$DSH_HOME` 配置层（settings.yaml 等）默认不动（`--include-home` 才还原）
- 🔒 **永不触碰**：会话数据、工作区文件
- ⚠️ 若文件在快照后被"原地改写"（不换 inode 的写法），硬链接会让快照同步被改——CLI 会如实报告并给出 lockfile 重建路径（`pnpm install --frozen-lockfile`）

### 命令面

```bash
node dsh-snap.mjs list | snapshot | restore | undo | verify | prune | doctor | crash | preflight | serve | open | where | state | selftest
```

- `verify [id|last|all] [--deep]`：快照完整性校验——快照侧文件被"原地改写"即污染指纹（硬链接方案的特有风险面，提前于还原检出）；`--deep` 逐文件比对快照期记录的 sha256
- `repair-gui` / `repair-profile`：官方"恢复插件"按钮造成次生破坏后的外科修复（bundles 回滚 + patch 原文恢复，全程 guard 备份、dry-run 预览；详见 `dsh-snap repair-gui --help`）
- `diff [idA] [idB]`：两个快照间的清单差异（省略 idB = 与最新快照对比）
- `doctor`：路径/同卷/句柄占用预检（test-rename 探针，与官方更新器同原语，#11119）/快照库完整性/半程还原检测/列车兼容自检
- `crash [--hours N]`：崩溃归因——崩溃日志解析 × journal 时间窗关联 → 嫌疑插件（direct/circumstantial 分级）+ 崩溃循环检测 + 指向崩溃前快照的还原命令；只报告不动手，无日志时纯 journal 关联
- `preflight <pkg>`：装前体检——registry 元数据（存在性/弃用标记/engines.dsh vs 本机 harness 版本）；零依赖 semver 子集，只告警不阻断
- `serve [--port N]`：救援台网页——仅本机回环 + 随机 token；快照列表/立即快照/体检/校验/崩溃归因/两步制还原（预览→确认）；DSH 完全起不来时浏览器还能用
- `prune`：保留策略（默认 15 个 / 3GB / 30 天；手动快照与 guard 快照豁免——用户显式还原点永不被自动清理）
- `open`：资源管理器打开快照库
- 会话内命令：`/snap list | now [备注] | doctor`；`npm i -g dsh-snap` 后可直接 `dsh-snap <命令>`（bin 入口）
- agent 工具：`snap_list` / `snap_snapshot` / `snap_doctor`（只读+安全面；还原刻意不进 agent 工具面——不让 LLM 触发破坏性操作）

### 隐私与安全边界

- 快照只写本机快照库；**唯一网络请求** = 装前体检查 registry 元数据（包存在性/engines/弃用标记，不发任何本机数据，TTL 缓存 6h，`config.preflight: false` 可整段关闭）
- 只读源文件；删除只发生在快照库内部，且 junction/symlink 只删链接本体（绝不跟随——45GB junction 跟随删除事故的根因防线）
- 崩溃归因纯只读：只读崩溃日志头部（≤4MB 截读）与自己的 journal，零写调用
- home 层快照前扫描凭据类键（token/apiKey/secret/password 等）——命中整文件不入库（快照库明文落盘，凭据不进去）
- pnpm 已知"原地重写"文件（node_modules/.modules.yaml）与 dsh-snap 自目录强制私有副本，不入硬链接池（0.3.6 两次实测修复：曾分别污染全部历史快照与自升级链）
- 双击营救 bat 优先使用 DSH 自带 runtime 的 node，PATH 里没有 node 也能跑
- 还原进度落盘：中途被杀=下次运行检出半程并指引重跑/撤销
- 所有自动快照可在设置页关闭策略开关（cordis.patch.yml 的 config 字段）；`snapshotIntervalHours` 定时轻量快照默认关闭

### 与其它插件分工（不内卷）

| 插件 | 它管的 | dsh-snap 管的 |
|---|---|---|
| dsh-checkpoint-rewind | 对话/工作区步骤回滚（git/copy） | 插件安装域 + 外部 CLI 营救 |
| @noob-stupid/dsh-plugin-console（gating-hub） | 框架升级回滚、启动备份 | 装插件/首装事件快照（它明确不接管首装） |
| @xiaoyuyu6420/dsh-backup | 整机定时备份（GB 级）、整机还原 | 装前轻量快照（秒级增量硬链接）+ 点还原 |
| dsh-lifeguard | 崩溃规则沉淀、自愈停用元凶（动手） | 崩溃归因只报告（不动手）+ 装前快照兜底 |
| dsh-fix | 独立急救 CLI（修 patch 层） | 快照还原器（数据层而非 patch 层） |
| dsh-restart-guard | 崩溃自动重启守护 | 还原与救援（自动重启坏插件环境=循环崩，刻意不做） |

### 工作原理

双层形态：**外部还原器 CLI 内核**（零依赖单文件 `cli/dsh-snap.mjs`，常驻快照库）+ **Cordis 插件**（事件触发 / Web 面板 / 命令）。快照 = profile 清单全拷贝（KB 级）+ node_modules 增量硬链接（同卷零成本，实测 11,872 文件 2.8 秒；pnpm 安装是"替换不原地改"语义，硬链接安全）。manifest 与文件索引在事务点同步落盘。保留策略硬性 GC。

### 质量与验证

- `npm test` 三套件：55 项内核 selftest + 宿主半侧冒烟 + 20 场景社区故障注入（全零依赖，Node ≥20 即可跑）
- 六轮"真崩溃"演练：5 种进程级死法（process.exit / 延迟 throw / 挂死 / 双 OOM / 语法错误），还原 6/6
- 136 个真实社区插件（npm 月下载 >5000 或 GitHub 星 >1000 全集）批量演练：快照保真 33/34、回滚清洁 34/34
- 两轮独立代码审计：合计 37 项发现全部修复（含 3 个 P0 信任边界问题），变异探针固化为回归测试

## English

**dsh-snap**: automatic pre-install snapshots for DSH plugins + an external zero-dependency CLI that restores you to the pre-install state even when DSH cannot boot. Snapshots trigger on agent installs (`tools/pre-execute`), Web-UI installs (`plugin-manager/install-state`), best-effort on CLI installs (`.plugin-manager/run.json`), and manually. Restore = manifest rewrite + hardlink backfill of node_modules, always preceded by a guard snapshot (restore is itself undoable). Sessions and workspace files are never touched; dangerous items are reported, never acted upon.

```bash
node "<store>/cli/dsh-snap.mjs" list | snapshot | restore last | undo | prune | doctor
```

Store: `$DSH_HOME/../.dsh-snap/` (same volume as the profile, outside `$DSH_HOME`; override with `DSH_SNAP_HOME`).

### Why

A broken plugin can take the whole harness down. The official toolchain covers post-hoc diagnosis (engine gates, install-failure diagnostics, hot-reload rollback) but there is no official "snapshot before the action + restore from outside" primitive. Every neighboring ecosystem (Claude Code / Cursor / OpenCode / VS Code / Home Assistant) ships checkpoint-and-restore built in — dsh-snap fills that gap for DSH.

### Privacy & safety boundary

- Snapshots stay on your disk. The only network request is preflight metadata from the npm registry (package existence / engines / deprecation flags; no local data leaves the machine; disable via `config.preflight: false`).
- Read-only toward your files; deletions only happen inside the snapshot store, and junctions/symlinks are never followed.
- Credential-looking keys in home-layer configs are scanned before snapshotting — files with hits never enter the store.
- Crash attribution is read-only; restore always takes a guard snapshot first, so it is undoable.

---

## Contributing & Support

- Bug reports / feature ideas: [Issues](../../issues) (模板见 `.github/ISSUE_TEMPLATE`)
- 修复与改进欢迎 PR；提交前跑 `npm test`（三套件全绿）
- 安全问题请勿公开提 issue，见 [SECURITY.md](SECURITY.md)

---

*License: MIT. 本插件与 DeepSeek 官方无关，是社区第三方工具。This is an unofficial community project, not affiliated with or endorsed by DeepSeek.*
