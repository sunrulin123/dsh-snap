/**
 * dsh-snap — Host 半侧。
 *
 * "装插件搞崩，一键回到装前。"
 *
 * 职责（触发与记录；快照/还原执行体在 cli/dsh-snap.mjs，插件与其共用一套代码）：
 *
 *   1. agent 路径：ctx.on('tools/pre-execute', {prepend:true}) 拦截 plugin_manager
 *      的 install_bundle / remove_bundle（全量快照）与 set_plugin / set_bundle
 *      （清单层快照），在工具执行**之前**拍快照 —— 事务点落盘纪律。
 *   2. Web 路径：ctx.on('plugin-manager/install-state') phase=installing 且
 *      attempt.index===1（pnpm 动 node_modules 之前）拍全量快照。
 *   3. CLI 路径（dsh plugin add 独立进程，无事件可得）：fs.watch 监视
 *      .plugin-manager/run.json 出现即尽力快照；与 pnpm 的竞态由 changed 对账纠偏。
 *   4. ctx.on('plugin-manager/changed')：完成后 diff 清单 → journal 对账、
 *      回填最近装前快照的 spec（UI 显示"这个快照是装 XXX 前拍的"）、后台 prune。
 *   5. 崩溃检测（Chrome exit_type 模式）：启动登记 state.json，dispose 写净退出；
 *      下次启动发现上次未净退出 → journal 记 crash-detected 并告警。
 *   6. 基线快照：无任何快照时，detached 子进程拍一次基线（不阻塞启动）。
 *
 * 克制纪律：
 *   · 快照失败绝不阻断工具执行（安全网不是闸门 —— checkpoint-rewind D1 模式）。
 *   · 还原刻意不进命令面：还原是"DSH 出问题后"的动作，执行体是外部 CLI
 *     （DSH 完全起不来也能跑）；client 半 UI 只负责唤起外部 CLI 并提示先退出 DSH。
 *   · 会话数据与工作区文件永不触碰。
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, watch, writeFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const NS = 'dsh-snap'
const PLUGIN_DIR = dirname(fileURLToPath(import.meta.url))

/** 安装类动作：全量快照（node_modules 层含）。 */
const INSTALL_ACTIONS = new Set(['install_bundle', 'remove_bundle'])
/** 开关类动作：只影响 patch 层，清单快照即可。 */
const TOGGLE_ACTIONS = new Set(['set_plugin', 'set_bundle'])

/* ============================================================
 * state.json / journal 轻量读写（与 cli/dsh-snap.mjs 的格式一致）
 * ============================================================ */

function readState(store, profileName) {
  // 先读按 profile 分文件的新格式；再回退旧的单文件 state.json
  try { return JSON.parse(readFileSync(join(store, `state-${profileName}.json`), 'utf8')) } catch { /* fallthrough */ }
  try {
    const legacy = JSON.parse(readFileSync(join(store, 'state.json'), 'utf8'))
    // legacy 无 profile 字段：视作本 profile 的历史（旧版单文件时代只有单 profile 在用）。
    // 显式 profile 且不匹配 → 不采信（跨 profile 误报防线）。
    if (!legacy.profile || legacy.profile === profileName) return legacy
  } catch { /* 无历史状态 */ }
  return null
}
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  if (pid === process.pid) return true
  try { process.kill(pid, 0); return true } catch (e) { return e.code === 'EPERM' }
}
function writeJsonAtomic(path, value) {
  const tmp = `${path}.tmp-${process.pid}-${Math.random().toString(36).slice(2, 8)}`
  try {
    writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', 'utf8')
    renameSync(tmp, path)
  } catch { /* 并发写竞态可容忍 */ }
}
function appendJournalLine(store, entry) {
  try {
    const dir = join(store, 'journal')
    mkdirSync(dir, { recursive: true })
    appendFileSync(join(dir, 'manifest-journal.jsonl'), JSON.stringify({ time: new Date().toISOString(), ...entry }) + '\n')
  } catch { /* journal 失败不阻塞主流程 */ }
}

/** 读 journal（撕裂行容忍；启动补 diff 用） */
function readJournalLike(store) {
  try {
    return readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')
      .split('\n').filter((l) => l.trim()).map((l) => { try { return JSON.parse(l) } catch { return {} } })
  } catch { return [] }
}

/** node_modules 顶层近窗新变包（mtime 哨兵，与内核 nmMtimeEvents 同语义的宿主侧轻量版） */
function nmNewPackages(profileDir, fromMs, toMs) {
  const out = []
  const nm = join(profileDir, 'node_modules')
  const scan = (parent, prefix) => {
    let entries = []
    try { entries = existsSync(parent) ? readdirSync(parent) : [] } catch { return }
    for (const entry of entries) {
      if (entry.startsWith('.')) continue
      const p = join(parent, entry)
      let st; try { st = statSync(p) } catch { continue }
      if (!st.isDirectory()) continue
      const mt = Math.floor(st.mtimeMs)
      if (mt >= fromMs - 30 * 60_000 && mt <= toMs + 5_000) {
        if (prefix) out.push(`${prefix}/${entry}`)
        else if (entry.startsWith('@')) scan(p, entry)
        else out.push(entry)
      } else if (!prefix && entry.startsWith('@')) scan(p, entry)
    }
  }
  scan(nm, null)
  return out
}
function readDeps(profileDir) {
  try {
    const m = JSON.parse(readFileSync(join(profileDir, 'package.json'), 'utf8'))
    return m.dependencies ?? {}
  } catch { return {} }
}

/** 运行快照内核（in-process 动态 import；**只用包内副本**）。
 * A4（0.7.4 审计 P1）：曾回退到 <store>/cli/dsh-snap.mjs 营救副本——该副本在可写目录，
 * 被篡改后宿主每次启动/对账都在执行攻击者代码（版本 marker 不是内容完整性证明）。
 * 包内副本随版本更新、随包完整性交付；store 副本只供用户在 DSH 完全起不来时
 * **显式手动**营救，宿主永远不执行它。 */
function loadKernel(store) {
  void store // 兼容旧签名（store 形参曾是回退路径依据）
  const p = join(PLUGIN_DIR, 'cli', 'dsh-snap.mjs')
  return (async () => {
    try { return await import(pathToFileURL(p).href) } catch (e) { throw e instanceof Error ? e : new Error(String(e)) }
  })()
}

/** 子进程用内核路径：**只用包内本体**（A4 同源：store 副本可写，不得作为执行体）。
 * 包内本体缺失是安装损坏，直接让调用方拿到 null 走报错路径，绝不回退 store。 */
function kernelCliPath(store) {
  void store
  return join(PLUGIN_DIR, 'cli', 'dsh-snap.mjs')
}

function newestSnapshotId(kernel, store) {
  return kernel.listSnapshots(store).find((m) => !m.corrupted)?.id ?? undefined
}

/** 清除 harness-state 档案里的 pendingBaseline 标记（基线快照成功后调用；ESM 无 require，用顶层 import 的 fs） */
function clearPendingBaseline(store, profileName) {
  try {
    const f = join(store, `harness-state-${profileName}.json`)
    const rec = JSON.parse(readFileSync(f, 'utf8'))
    if (rec.pendingBaseline === undefined) return
    delete rec.pendingBaseline
    writeJsonAtomic(f, rec)
  } catch { /* 清标记失败可容忍：下次启动多拍一次基线 */ }
}

/** 给子进程的显式环境（桌面端进程常无 DSH_HOME env，必须显式传）。
 * ELECTRON_RUN_AS_NODE=1：宿主是 Electron 二进制时 spawn(process.execPath) 才跑 node
 * 而不是拉起 GUI（node 模式宿主下该 env 已存在，重设无害） */
function childEnv(dshHome, profileName, store) {
  return { ...process.env, DSH_HOME: dshHome, DSH_PROFILE: profileName, DSH_SNAP_HOME: store, ELECTRON_RUN_AS_NODE: '1' }
}

/**
 * 插件入口。
 * @param {object} ctx cordis 上下文。
 * @param {object|undefined} config cordis.patch.yml 条目里的 config 字段。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  const prof = ctx.profileContext
  if (!prof?.dir) {
    ctx.logger?.warn?.('[dsh-snap] 无 profileContext，插件不生效（请用外部 CLI）')
    return
  }
  const profile = { name: prof.name, dir: prof.dir }
  const dshHome = prof.home || dirname(dirname(prof.dir))
  const store = process.env.DSH_SNAP_HOME || join(dirname(dshHome), '.dsh-snap')
  const log = (level, msg, ...rest) => {
    try { ctx.logger?.[level]?.(`[dsh-snap] ${msg}`, ...rest) } catch { /* logger 缺失可容忍 */ }
  }
  const disposables = []

  /* ---- store 初始化 ---- */
  try {
    for (const d of ['snapshots', 'journal', 'cli']) mkdirSync(join(store, d), { recursive: true })
  } catch (e) {
    log('error', `快照库初始化失败：${e?.message}。可用 DSH_SNAP_HOME 指定其它位置`)
    return
  }

  /* ---- 崩溃检测（Chrome exit_type 模式；按 profile 分文件，多 profile 互不覆盖） ---- */
  const stateFile = join(store, `state-${profile.name}.json`)
  const prev = readState(store, profile.name)
  const prevUnclean = !!(prev && prev.cleanExit === false && !pidAlive(prev.pid))
  // fatal-clean 信号：进程走净退清理但 exitCode 非零（如 cordis 对 fatal uncaught 的优雅收场
  // ——演练 R4 实证：OOM 崩溃 cleanExit:true，不留任何未净退出痕迹，归因链完全失明）
  const prevFatalClean = !!(prev && prev.cleanExit === true && Number(prev.exitCode ?? 0) !== 0)
  const ownBootId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  writeJsonAtomic(stateFile, {
    bootId: ownBootId,
    pid: process.pid,
    profile: profile.name,
    startedAt: Date.now(),
    bootTimeWall: Date.now(), // 墙钟：还原侧用进程创建时间核验 pid（防 Windows pid 复用）
    cleanExit: false,
  })
  if (prevUnclean || prevFatalClean) {
    appendJournalLine(store, {
      kind: 'crash-detected',
      profile: profile.name,
      prevBootId: prev.bootId,
      prevStartedAt: prev.startedAt ? new Date(prev.startedAt).toISOString() : null,
      fatalExit: prevFatalClean || undefined,
      prevExitCode: prevFatalClean ? Number(prev.exitCode ?? 0) : undefined,
      fatalReason: prevFatalClean ? prev.fatalReason : undefined, // R4：死因明文（OOM等），归因升级 kind 用
      note: prevFatalClean
        ? `上次运行以致命错误收场（exitCode=${prev.exitCode}${prev.fatalReason ? `：${prev.fatalReason}` : ''}）。如怀疑插件导致，可用外部 CLI 还原：node <store>/cli/dsh-snap.mjs restore last`
        : '上次运行未净退出（进程死亡）。如怀疑插件导致，可用外部 CLI 还原：node <store>/cli/dsh-snap.mjs restore last',
    })
    if (prevFatalClean) {
      log('warn', `上次运行以致命错误收场（exitCode=${prev.exitCode}）。若怀疑插件导致，可还原到最近快照：node`, join(store, 'cli', 'dsh-snap.mjs'), 'restore last')
    } else {
      log('warn', '上次运行未净退出（可能是崩溃）。若怀疑插件导致，可还原到最近快照：node', join(store, 'cli', 'dsh-snap.mjs'), 'restore last')
    }
    /* G5 崩溃归因：启动时归因一次，只增告警措辞，不阻塞（fire-and-forget） */
    loadKernel(store).then((k) => {
      const a = k.attributeCrash ? k.attributeCrash({ dshHome, store, profile }) : null
      const s = a?.suspects?.[0]
      if (s) log('warn', `崩溃归因：疑似相关插件 ${s.pkg}（${s.confidence}）；还原命令与完整证据见面板或 CLI crash 子命令`)
      for (const l of (a?.loops ?? []).slice(0, 1)) log('warn', `崩溃循环：24h 内 ${l.count} 次（${l.first} → ${l.last}）`)
    }).catch(() => { /* 归因失败静默 */ })
  }

  /* ---- 快照执行器（事件回调内 await；内核加载失败降级为仅 journal） ---- */
  const takeSnap = (trigger, { nodeModules = true, spec = null, note = null } = {}) => {
    return loadKernel(store).then((k) => {
      const manifest = k.takeSnapshot({
        store, profile, dshHome, trigger, spec, note,
        nodeModules,
        prevId: newestSnapshotId(k, store),
      })
      log('info', `快照 ${manifest.id} 完成（trigger=${trigger}，${manifest.stats.files} 文件，${manifest.stats.durationMs}ms）`)
      return manifest
    }).catch((e) => {
      log('warn', `快照失败（trigger=${trigger}）：${e?.message}。继续原操作，稍后可用 CLI 手动补拍`)
      appendJournalLine(store, { kind: 'snapshot-failed', trigger, error: String(e?.message || e) })
      return null
    })
  }

  /* ---- harness 变更哨兵（破坏性更新防线）：启动时比对环境指纹，变化即 journal + 基线快照 ----
   * 桌面版更新频繁（0.2 列车实测约每 3-5 天一个 rc），破坏性更新后插件兼容性破裂是
   * 「更新后首启故障」的主要来源。哨兵让每次 harness 变化都有：证据行 + 更新后基线还原点。 */
  loadKernel(store).then((k) => {
    if (!k.detectHarnessChange) return
    const det = k.detectHarnessChange(dshHome, profile, store)
    // pendingBaseline：上次变更写回了指纹但基线快照被截断（启动失败/秒退）→ 本次补拍
    if (!det.changed && det.pendingBaseline && det.cur) {
      log('warn', '检测到未完成的 harness-change 基线快照（上次启动被截断），本次补拍')
      try {
        // takeSnapshot 是同步函数（内核 0.7.1+ P1-05 勘误：曾对返回 manifest 调 .then → TypeError，
        // 补拍永远失败且被 catch 静默吞掉——宿主冒烟未覆盖此路径）
        const m = k.takeSnapshot({
          store, profile, dshHome, trigger: 'harness-change',
          note: 'harness 环境变化自动基线（补拍）',
          nodeModules: true,
          prevId: newestSnapshotId(k, store),
        })
        log('info', `harness-change 补拍基线快照 ${m.id} 完成（${m.stats.files} 文件）`)
        clearPendingBaseline(store, profile.name)
      } catch (e) {
        log('warn', `harness-change 补拍失败：${e?.message}（保持 pending，下次启动再补）`)
      }
      return
    }
    if (!det.changed) {
      // 首启或无变化：建档（首启时 cur 已算好；无变化也顺手刷新 savedAt，不写 journal）
      if (det.cur && (!det.savedAt || !det.saved)) k.saveHarnessState(dshHome, profile, store, det.cur, { firstSeen: !det.saved })
      return
    }
    // 先写回指纹再拍快照（顺序纪律）：宿主启动失败/秒退时 fire-and-forget 链会被截断，
    // 快照完成前的写回先落地——否则下次启动指纹仍旧会重复拍基线（U-0 演练实证：EADDRINUSE
    // 秒退宿主截断 then 链，journal/快照都在、指纹回写丢失）。
    // pendingBaseline 标记恒置 true：写回了但快照没拍成 → 下次启动补拍一次（快照成功后
    // clearPendingBaseline 清除）。曾误从 state 文件读 hadPending 做防重——state 文件永不
    // 含该标记，守卫恒 false 等于死代码；且条件写回会把已存在的 pending 覆盖清除。
    k.saveHarnessState(dshHome, profile, store, det.to, { pendingBaseline: true })
    appendJournalLine(store, {
      kind: 'harness-change',
      profile: profile.name,
      from: { harnessDeps: det.from.harnessDeps, runtime: det.from.runtime ? String(det.from.runtime).slice(0, 12) : null, app: det.from.app ? String(det.from.app).split('|')[0] : null },
      to: { harnessDeps: det.to.harnessDeps, runtime: det.to.runtime ? String(det.to.runtime).slice(0, 12) : null, app: det.to.app ? String(det.to.app).split('|')[0] : null },
      savedAt: det.savedAt,
      note: 'harness 环境变化（桌面版更新/运行时更新/依赖重解析）。更新后首启故障可归因此事件；已自动拍基线快照',
    })
    log('warn', '检测到 harness 环境变化（桌面版更新？）。已自动拍基线快照；若更新后出现插件故障，可还原到更新前快照对比')
    try {
      // takeSnapshot 是同步函数（P1-05 同上：.then on manifest 曾让基线快照永远失败）
      const m = k.takeSnapshot({
        store, profile, dshHome, trigger: 'harness-change',
        note: 'harness 环境变化自动基线（更新后首启）',
        nodeModules: true,
        prevId: newestSnapshotId(k, store),
      })
      log('info', `harness-change 基线快照 ${m.id} 完成（${m.stats.files} 文件）`)
      clearPendingBaseline(store, profile.name)
    } catch (e) {
      log('warn', `harness-change 基线快照失败：${e?.message}（指纹已记录，下次启动补拍基线；journal 有证据行）`)
      // pendingBaseline 保持 → 下次启动补拍
    }
  }).catch(() => { /* 哨兵失败静默——绝不影响启动 */ })

  /* ---- G8 装前体检：fire-and-forget，绝不 delay 安装（只告警不阻断） ---- */
  const runPreflight = (spec) => {
    if (cfg.preflight === false) return
    loadKernel(store).then((k) => {
      if (!k.preflightPackage) return
      return k.preflightPackage({ spec, profile, store })
    }).then((r) => {
      if (!r) return
      const warns = r.checks.filter((c) => !c.ok)
      appendJournalLine(store, { kind: 'preflight', spec: r.spec, name: r.name, ok: r.ok, warns: warns.map((c) => `${c.id}: ${c.detail}`), profile: profile.name })
      if (warns.length) log('warn', `装前体检（不阻断）：装 ${r.spec} 前 ${warns.length} 项注意 → ${warns.map((c) => c.id).join(', ')}；详情见 journal`)
    }).catch(() => { /* 预检永不 reject；兜底仍不阻断 */ })
  }

  /* ---- 1. agent 路径：tools/pre-execute 拦截（prepend 直通） ---- */
  try {
    ctx.on('tools/pre-execute', (exec, next) => {
      try {
        const action = exec?.arguments?.action
        if (exec?.name !== 'plugin_manager' || typeof action !== 'string') return next()
        const isInstall = INSTALL_ACTIONS.has(action)
        const isToggle = TOGGLE_ACTIONS.has(action)
        if (!isInstall && !isToggle) return next()
        if (cfg.snapshotOnInstall === false) return next()
        const spec = typeof exec.arguments.target === 'string' ? exec.arguments.target : null
        const done = takeSnap(`agent:${action}${spec ? `:${spec}` : ''}`, {
          // 开关类动作默认只拍清单层（node_modules 未变）；manifestOnlyForToggles:false 才全量
          nodeModules: isInstall || cfg.manifestOnlyForToggles === false,
          spec,
        })
        if (isInstall && spec && action === 'install_bundle') runPreflight(spec) // 并行发射：不进入 next() 等待链
        return done.then(() => next()) // done 永不 reject（内部已捕获）——安全网非闸门
      } catch {
        return next()
      }
    }, { prepend: true })
    log('info', 'agent 路径拦截已挂载（tools/pre-execute prepend）')
  } catch (e) {
    log('warn', `tools/pre-execute 挂载失败（宿主无该事件？）：${e?.message}`)
  }

  /* ---- 2. Web 路径：plugin-manager/install-state（requestId 存在时才发） ---- */
  const seenRequests = new Set()
  try {
    ctx.on('plugin-manager/install-state', (progress) => {
      try {
        if (progress?.phase !== 'installing' || progress.attempt?.index !== 1) return
        if (progress.requestId === undefined || seenRequests.has(progress.requestId)) return
        seenRequests.add(progress.requestId)
        if (seenRequests.size > 64) seenRequests.delete(seenRequests.values().next().value)
        takeSnap('web-install')
      } catch { /* 快照失败不阻塞安装 */ }
    })
  } catch { /* 老宿主无该事件：agent/CLI 路径仍在 */ }

  /* ---- 2.5 Web 预检：install-state 负载无包名，加挂 plugin-manager/operation
          （parallel 模式，phase=started 先于 pnpm；target=解析出的 registry 包名） ---- */
  try {
    ctx.on('plugin-manager/operation', (op) => {
      try {
        if (op?.phase !== 'started' || op.reason !== 'install') return // remove/toggle 不预检
        if (typeof op.target !== 'string' || !op.target) return
        runPreflight(op.target) // parallel 事件，不阻塞管理器
      } catch { /* 预检失败不阻塞 */ }
    })
  } catch { /* 老宿主无该事件：agent/CLI 路径仍在 */ }

  /* ---- 3. CLI 路径：.plugin-manager/run.json 监视器 ---- */
  let cliWatcher = null
  let cliRetryTimer = null
  let cliDiffTimer = null
  const closeCliWatcher = () => { try { cliWatcher?.close() } catch { /* 忽略 */ } cliWatcher = null }
  const clearCliDiffTimer = () => { if (cliDiffTimer) { try { clearTimeout(cliDiffTimer) } catch { /* 忽略 */ } cliDiffTimer = null } }
  // R4 演练实证：CLI 安装（独立进程）不触发宿主的 plugin-manager/changed，
  // 包名因此缺席 journal → 崩溃归因对 CLI 装的凶器失明。
  // 修复：cli-install 触发后延迟 diff 依赖清单，把 added/removed 以 manifest-change
  // 形态补进 journal（归因的 pkgEventsOf 直接消费），并回填最近装前快照的 spec。
  const scheduleCliDiff = () => {
    clearCliDiffTimer()
    cliDiffTimer = setTimeout(() => {
      cliDiffTimer = null
      try {
        const nowDeps = readDeps(prof.dir)
        const before = lastDeps
        lastDeps = nowDeps
        const added = Object.keys(nowDeps).filter((k) => before[k] !== nowDeps[k])
        const removed = Object.keys(before).filter((k) => nowDeps[k] !== before[k] && !added.includes(k))
        if (!added.length && !removed.length) return // pnpm 未动清单 / 已被 changed 事件对账
        appendJournalLine(store, { kind: 'manifest-change', reason: 'cli', added, removed, profile: profile.name })
        if (added.length) stampNewestPreInstallSpec(store, added)
      } catch { /* 对账失败不阻塞 */ }
    }, 45000)
  }
  const armCliWatch = () => {
    if (cfg.watchCli === false) return
    const dir = join(prof.dir, '.plugin-manager')
    if (!existsSync(dir)) {
      cliRetryTimer = setTimeout(armCliWatch, 5000) // 目录还没建（从未装过插件），稍后再试
      try { cliRetryTimer.unref?.() } catch { /* 老.node */ }
      return
    }
    const runRecord = join(dir, 'run.json')
    // episode 状态机：run.json 的创建/更新/删除都触发本回调（ReadDirectoryChangesW 语义）。
    // 只在 absent→present 边沿拍竞态快照——旧实现只靠 30s 去重窗，长安装（>30s）结束时的
    // 更新/删除事件会再拍一张**装后**快照，同为 trigger=cli-install，spec 回填与面板二分
    // 还原指引都会指到装后状态（违背"一键回到装前"承诺）。
    let inEpisode = existsSync(runRecord) // 接管时已存在（陈旧记录/装到一半）：本轮不拍，等下一个完整 episode（启动补对账兜底）
    try {
      cliWatcher = watch(dir, (event, filename) => {
        if (filename !== 'run.json') return
        const present = existsSync(runRecord)
        if (!present) { inEpisode = false; return } // 删除事件：episode 结束
        if (inEpisode) return // episode 内的更新事件：装中，不重复拍
        inEpisode = true
        takeSnap('cli-install', { note: 'CLI 安装路径竞态快照：pnpm 可能已开始写盘，以 journal 对账为准' })
        scheduleCliDiff()
      })
      cliWatcher.on('error', () => {
        closeCliWatcher()
        cliRetryTimer = setTimeout(armCliWatch, 10000)
        try { cliRetryTimer.unref?.() } catch { /* 老.node */ }
      })
    } catch { /* watch 失败可容忍 */ }
  }
  armCliWatch()

  /* ---- 3.5 启动补 diff（U 系列演练实证）：CLI 装包后宿主被重启 → 45s diff timer 随旧进程
          死亡，manifest-change 永久缺席。启动时若 journal 末尾是 cli-install 快照且其后
          无 manifest-change，补跑一次 diff（新宿主的 lastDeps 已含装包后清单，
          需要以「装包前」为基线——用 journal 里最近 cli-install 快照前的 deps 快照不可得，
          退而求其次：把 nm-mtime 哨兵抓到的近 30min 新增包直接落 manifest-change 行）。 ---- */
  try {
    loadKernel(store).then((k0) => {
      if (!k0?.listSnapshots) return
      const snaps = k0.listSnapshots(store).filter((m) => !m.corrupted)
      const lastCli = snaps.find((m) => m.trigger === 'cli-install')
      if (!lastCli) return
      const lastCliMs = Date.parse(lastCli.time)
      const hasChange = readJournalLike(store).some((e) => e.kind === 'manifest-change' && Date.parse(e.time ?? '') >= lastCliMs)
      if (hasChange) return
      try {
        const nms = nmNewPackages(prof.dir, lastCliMs, Date.now())
        if (nms.length) {
          // removed 恒空是设计限界：删掉的包目录已不在磁盘，nm-mtime 看不见；
          // 该场景的归因兜底 = CLI 路径 pnpm 自己的 journal 对账（若 changed 事件曾触发）
          appendJournalLine(store, { kind: 'manifest-change', reason: 'cli', added: nms, removed: [], profile: profile.name, note: '启动补对账：上次 CLI 装包的 45s diff 随宿主重启丢失' })
          log('info', `启动补对账：CLI 装包 ${nms.join(', ')} 已补进 journal`)
        }
      } catch { /* 补对账失败可容忍（nm-mtime 哨兵在归因侧兜底） */ }
    }).catch(() => { /* 永不阻塞启动 */ })
  } catch { /* 永不阻塞启动 */ }

  /* ---- 4. changed 对账：diff 清单 → journal + 回填 spec + 后台 prune ---- */
  let lastDeps = readDeps(prof.dir)
  try {
    ctx.on('plugin-manager/changed', (change) => {
      try {
        const nowDeps = readDeps(prof.dir)
        const before = lastDeps
        lastDeps = nowDeps
        const added = Object.keys(nowDeps).filter((k) => before[k] !== nowDeps[k])
        const removed = Object.keys(before).filter((k) => nowDeps[k] !== before[k] && !added.includes(k))
        appendJournalLine(store, { kind: 'manifest-change', reason: change?.reason ?? null, added, removed, profile: profile.name })
        if (added.length && (change?.reason === 'install' || change?.reason === 'plugin')) {
          stampNewestPreInstallSpec(store, added)
        }
        spawn(process.execPath, [kernelCliPath(store), 'prune'], {
          detached: true, stdio: 'ignore', env: childEnv(dshHome, profile.name, store),
        }).on('error', () => { /* P3-9：EMFILE/EACCES 等罕见失败不成宿主级 uncaught */ }).unref()
      } catch { /* 对账失败不阻塞 */ }
    })
  } catch { /* 老宿主无该事件 */ }

  /** 把"这次装的是什么"回填到最近的装前快照 manifest（UI 显示用） */
  function stampNewestPreInstallSpec(store_, added) {
    loadKernel(store_).then((k) => {
      const snaps = k.listSnapshots(store_).filter((m) => !m.corrupted)
      const candidate = snaps.find((m) =>
        (typeof m.trigger === 'string' && m.trigger.startsWith('agent:install'))
        || m.trigger === 'web-install' || m.trigger === 'cli-install')
      if (!candidate) return
      const manifestPath = join(store_, 'snapshots', candidate.id, 'manifest.json')
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
      if (manifest.spec) return // agent 路径直接带了 spec
      manifest.spec = added.join(', ')
      manifest.specSource = 'post-install-diff'
      writeJsonAtomic(manifestPath, manifest)
    }).catch(() => { /* 回填失败可容忍 */ })
  }

  /* ---- 4.5 HMR 事件：补 journal 盲区（手改 profile 文件 + 插件热重载） ---- */
  let lastHmrChangeAt = 0
  try {
    ctx.on('hmr/change', (url) => {
      try {
        // 只关心 profile 目录内的文件（HMR 也可能报其它路径）；10s 节流防噪音
        if (typeof url !== 'string') return
        let file = null
        try { file = fileURLToPath(url) } catch { return }
        const norm = file.toLowerCase()
        const profNorm = prof.dir.toLowerCase()
        if (!norm.startsWith(profNorm)) return
        const now = Date.now()
        if (now - lastHmrChangeAt < 10000) return
        lastHmrChangeAt = now
        appendJournalLine(store, { kind: 'hmr-change', file, note: 'profile 文件被手改/外部程序改动（非管理器操作）——建议手动拍一次快照' })
      } catch { /* journal 失败不阻塞 */ }
    })
  } catch { /* 老宿主无该事件 */ }
  try {
    ctx.on('hmr/reload', (reloads) => {
      try {
        const names = []
        if (reloads && typeof reloads.forEach === 'function') {
          reloads.forEach((_reload, plugin) => { names.push(plugin?.name || String(plugin)) })
        }
        appendJournalLine(store, { kind: 'hmr-reload', plugins: names })
      } catch { /* journal 失败不阻塞 */ }
    })
  } catch { /* 老宿主无该事件 */ }

  /* ---- 5. 基线快照（无任何快照时；detached 子进程不阻塞启动） ---- */
  if (cfg.baselineOnBoot !== false) {
    loadKernel(store).then((k) => {
      if (k.listSnapshots(store).some((m) => !m.corrupted)) return
      spawn(process.execPath, [kernelCliPath(store), 'snapshot', '--trigger', 'baseline', '--label', 'dsh-snap 初始基线'], {
        detached: true, stdio: 'ignore', env: childEnv(dshHome, profile.name, store),
      }).on('error', (e) => log('warn', `基线快照子进程启动失败：${e?.message}`)).unref()
      log('info', '首次安装：后台拍取初始基线快照（不阻塞启动）')
    }).catch((e) => log('warn', `基线快照调度失败：${e?.message}`))
  }

  /* ---- 5.5 定时轻量快照（G9）：仅清单有变化时才拍（避免无意义快照），非豁免入轮换池 ---- */
  let schedTimer = null
  let schedDisposed = false // P2-8：dispose 后不得重臂（定时器会阻止事件循环排空+卸载后永续）
  const clearSchedTimer = () => { if (schedTimer) { try { clearTimeout(schedTimer) } catch { /* 忽略 */ } schedTimer = null } }
  const scheduleNextSnap = () => {
    clearSchedTimer()
    const hours = Number(cfg.snapshotIntervalHours)
    if (!Number.isFinite(hours) || hours <= 0 || schedDisposed) return // 0/未配 = 关闭
    schedTimer = setTimeout(() => {
      Promise.resolve((async () => {
        try {
          const k = await loadKernel(store)
          const newest = k.listSnapshots(store).find((m) => !m.corrupted)
          const lastSnapMs = newest?.timeEpoch ?? 0
          // 变化判定：三件套任一 mtime 晚于最新快照 → 有变化才拍
          let changed = !newest
          for (const f of ['pnpm-lock.yaml', 'package.json', 'cordis.patch.yml']) {
            try { if (statSync(join(prof.dir, f)).mtimeMs > lastSnapMs) { changed = true; break } } catch { /* 文件不在 */ }
          }
          if (changed) await takeSnap('scheduled', { note: '定时轻量快照（清单有变化）' })
        } catch { /* 定时快照失败静默 */ }
      })()).then(() => { if (!schedDisposed) scheduleNextSnap() })
    }, Math.min(hours * 3600_000, 2 ** 31 - 1))
    try { schedTimer.unref?.() } catch { /* 老.node 无 unref 可容忍 */ }
    log('info', `定时快照已启用：每 ${hours}h 检查一次（仅清单有变化时拍）`)
  }
  scheduleNextSnap()
  disposables.push(clearSchedTimer) // 唯一一份：dispose 清当前 timer（重臂是复用变量，闭包幂等）

  /* ---- 6. /snap 命令（list / now / doctor；还原刻意不进命令面） ---- */  try {
    ctx.commands?.register?.({
      name: 'snap',
      description: 'dsh-snap: 快照列表 / 立即快照 / 环境体检。还原请用外部 CLI：node <快照库>\\cli\\dsh-snap.mjs restore last（DSH 起不来时也能跑）。',
      input: { hint: 'list | now [备注] | doctor' },
      async handler(invocation) {
        // E1（0.7.4 审计 P1）：真实 dsh-commands 传 invocation.rawInput（0.2 列车实证），
        // args/input 形参曾恒空 → /snap now|doctor 全部落到 list 分支
        const raw = String(invocation?.rawInput ?? invocation?.args ?? invocation?.input ?? '').trim()
        const sub = raw.split(/\s+/)[0] || 'list'
        const k = await loadKernel(store)
        if (sub === 'now') {
          const label = raw.slice(3).trim() || null
          const manifest = k.takeSnapshot({ store, profile, dshHome, trigger: 'manual', label })
          return `✅ 快照 ${manifest.id}：${manifest.stats.files} 文件 / ${manifest.stats.durationMs}ms`
        }
        if (sub === 'doctor') {
          const r = k.doctor(profile, dshHome) // 显式传 dshHome：desktop-host 常无 DSH_HOME env
          return r.checks.map((c) => `${c.ok ? '✅' : '⚠️'} ${c.id}: ${c.detail}`).join('\n')
        }
        const snaps = k.listSnapshots(store)
        if (!snaps.length) return '（快照库为空）'
        return snaps.slice(0, 12).map((m) => m.corrupted
          ? `${m.id}  ⚠️ 损坏`
          : `${m.id}  ${m.guard ? '[guard] ' : m.manual ? '[手动] ' : ''}${m.trigger}  ${m.spec ?? ''}  ${m.stats?.files ?? '?'}文件`).join('\n')
      },
    })
  } catch (e) {
    log('warn', `/snap 命令注册失败：${e?.message}`)
  }

  /* ---- 6.5 只读 agent 工具（G7）：让自然语言能驱动快照面。
          restore 刻意不进工具面——还原执行体是外部 CLI，且不让 LLM 触发破坏性操作 ---- */
  try {
    const tools = (() => {
      try { return typeof ctx.get === 'function' ? ctx.get('tools') : ctx.tools } catch { return undefined }
    })()
    if (tools && typeof tools.register === 'function') {
      const fmtList = (snaps) => snaps.slice(0, 12).map((m) => m.corrupted
        ? `${m.id}  ⚠️ 损坏`
        : `${m.id}  ${m.guard ? '[guard] ' : m.manual ? '[手动] ' : ''}${m.trigger}  ${m.spec ?? ''}  ${m.stats?.files ?? '?'}文件 ${new Date(m.time).toLocaleString?.() ?? m.time}`).join('\n')
      const toolDefs = [
        {
          name: 'snap_list',
          description: '列出 dsh-snap 快照时间线（时间/触发点/装的什么/规模）。用户问"最近装了什么/有没有快照/能不能回退"时先调它。还原不在此执行：DSH 完全退出后用外部 CLI node <快照库>\\cli\\dsh-snap.mjs restore last。',
          parameters: { type: 'object', properties: {}, additionalProperties: false },
          // E1（0.7.4 审计 P1）：当前 DSH 列车的 ToolsService 强制 output {schema, render}——
          // 缺失时 register 直接 throw，三个工具全部注册失败（却记"已注册"）
          output: {
            schema: { type: 'object', properties: { text: { type: 'string' }, total: { type: 'integer' } }, required: ['text'] },
            render: (args, value) => String(value?.text ?? ''),
          },
          execute: async () => {
            const k = await loadKernel(store)
            const snaps = k.listSnapshots(store)
            return { text: snaps.length ? fmtList(snaps) : '（快照库为空。装/删一个插件后会出现第一条。）', total: snaps.length }
          },
        },
        {
          name: 'snap_snapshot',
          description: '立即拍一份 dsh-snap 快照（只写快照库，不动 DSH 数据；手动快照永不被自动清理）。用户说"帮我拍个快照/保险一下"时调它。注意：不能替代安装前自动快照。',
          parameters: { type: 'object', properties: { label: { type: 'string', description: '可选备注，如"装 dsh-foo 前"' } }, additionalProperties: false },
          output: {
            schema: { type: 'object', properties: { text: { type: 'string' }, id: { type: 'string' } }, required: ['text', 'id'] },
            render: (args, value) => String(value?.text ?? ''),
          },
          execute: async (args) => {
            const k = await loadKernel(store)
            const manifest = k.takeSnapshot({ store, profile, dshHome, trigger: 'manual', label: typeof args?.label === 'string' && args.label ? args.label : 'agent 工具快照' })
            return { text: `✅ 快照 ${manifest.id}：${manifest.stats.files} 文件 / ${manifest.stats.durationMs}ms（手动快照，永不被自动清理）`, id: manifest.id }
          },
        },
        {
          name: 'snap_doctor',
          description: 'dsh-snap 环境体检：DSH_HOME/同卷/句柄占用预检/快照库完整性/半程还原/磁盘。用户说"帮我检查环境/怎么又出问题了"时调它；装插件前也可先跑一遍。',
          parameters: { type: 'object', properties: {}, additionalProperties: false },
          output: {
            schema: { type: 'object', properties: { text: { type: 'string' }, ok: { type: 'boolean' } }, required: ['text'] },
            render: (args, value) => String(value?.text ?? ''),
          },
          execute: async () => {
            const k = await loadKernel(store)
            const r = k.doctor(profile, dshHome)
            const lines = r.checks.map((c) => `${c.ok ? '✅' : '⚠️'} ${c.id}: ${c.detail}`)
            const bad = r.checks.filter((c) => !c.ok)
            return { text: `${bad.length ? `有 ${bad.length} 项告警（只报告不动手）` : '全部通过'}\n${lines.join('\n')}`, ok: r.ok }
          },
        },
      ]
      let registered = 0
      for (const def of toolDefs) {
        try {
          const d = tools.register(def)
          registered++
          if (typeof d === 'function') disposables.push(d)
        } catch (e) {
          log('warn', `agent 工具注册失败 ${def.name}：${e?.message}`)
        }
      }
      // E1：日志必须记真实成功数——曾无条件打印"已注册"（register throw 也显示成功）
      if (registered === toolDefs.length) log('info', `agent 工具已注册（${toolDefs.map((t) => t.name).join('/')}）`)
      else log('warn', `agent 工具注册不完整（${registered}/${toolDefs.length}）——宿主工具契约可能已变化`)
    } else {
      log('info', '宿主无 tools 服务，agent 工具面跳过（CLI/命令/面板可用）')
    }
  } catch (e) {
    log('warn', `agent 工具面挂载失败：${e?.message}`)
  }

  /* ---- 7. HTTP 路由（Web 半侧数据面；R3） ---- */
  const rejectCode = (req) => {
    // fail-closed：connection 信任栅栏服务缺失时拒绝（曾 fail-open——服务缺失即全放行）
    try {
      const connection = (typeof ctx.get === 'function' ? ctx.get('connection') : undefined) || ctx.connection
      if (!connection || typeof connection.requestRejection !== 'function') return 403
      const code = connection.requestRejection(req)
      if (code === undefined || code === null || code === false) return 0
      return typeof code === 'number' ? code : 403
    } catch { return 403 }
  }
  const sendJson = (res, code, payload) => {
    const body = Buffer.from(JSON.stringify(payload), 'utf8')
    res.writeHead(code, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Length': String(body.length),
    })
    res.end(body)
  }
  const jsonRoute = (routePath, produce, { method = 'GET' } = {}) => ({
    kind: 'exact',
    path: routePath,
    handler: async (req, res) => {
      const code = rejectCode(req)
      if (code !== 0) { res.writeHead(code); res.end(); return }
      if (method !== 'GET' && req.method !== method) { res.writeHead(405, { Allow: method }); res.end(); return }
      let payload
      try { payload = await produce(req) } catch (e) {
        payload = { ok: false, reason: 'error', message: String(e?.message || e).slice(0, 200) }
      }
      sendJson(res, 200, payload)
    },
  })

  const whenWebServer = (callback) => {
    let timer = null
    let tries = 0
    const stop = () => { if (timer !== null) { clearTimeout(timer); timer = null } }
    const tick = () => {
      timer = null
      let server = null
      try { server = typeof ctx.get === 'function' ? ctx.get('webServer') : undefined } catch { server = undefined }
      if (server && typeof server.register === 'function') { callback(server); return }
      if (++tries > 120) { log('warn', 'webServer 一直未就绪，面板路由未注册'); stop(); return }
      timer = setTimeout(tick, 500)
      try { timer.unref?.() } catch { /* 老.node */ } // 轮询不得阻止进程排空（webless 宿主/测试挂 60s 的根源）
    }
    tick()
    disposables.push(stop)
  }

  whenWebServer((server) => {
    const routes = [
      jsonRoute('/dsh-snap/panel', async () => {
        const k = await loadKernel(store)
        const snaps = k.listSnapshots(store)
        const st = readState(store, profile.name)
        let attribution = null
        try { attribution = k.attributeCrash ? k.attributeCrash({ dshHome, store, profile, snapshots: snaps }) : null } catch { /* 降级为无归因 */ } // snapshots 复用上方已解析列表（P1-01：曾二次全量解析 506×5.9MB manifest）
        return {
          ok: true,
          store,
          profile: profile.name,
          dshRunning: !!(st && st.cleanExit === false && pidAlive(st.pid) && st.pid !== process.pid),
          // E5（0.7.4 审计 P2）：fatal-clean（净退场但 exitCode 非零，如 OOM 优雅收场）也曾
          // 不显示崩溃横幅——用户看不到上次的致命收场提示
          uncleanBoot: prevUnclean || prevFatalClean,
          restoreHint: `node "${join(store, 'cli', 'dsh-snap.mjs')}" restore last`,
          batPath: join(store, 'cli', 'restore-last.bat'),
          attribution: attribution ? {
            journalOnly: !!attribution.sources?.journalOnly,
            crashes: (attribution.crashes ?? []).slice(0, 5).map((c) => ({ time: c.time, kind: c.kind, summary: c.summary, exitCode: c.exitCode })),
            suspects: (attribution.suspects ?? []).slice(0, 3).map((s) => ({ pkg: s.pkg, confidence: s.confidence, evidence: s.evidence, lastEventAt: s.lastEventAt, action: s.action })),
            loops: attribution.loops ?? [],
            shellHandshake: attribution.shellHandshake ?? null, // P2-03：0.7.2 曾在此被丢弃，Web 面板永远看不到外壳握手诊断
            restoreHint: attribution.restoreHint,
          } : null,
          harnessChange: (() => {
            try {
              const jc = k.readJournal ? k.readJournal(store).filter((e) => e.kind === 'harness-change' && e.profile === profile.name) : []
              return jc.length ? { count: jc.length, last: jc[jc.length - 1] } : null
            } catch { return null }
          })(),
          snapshots: snaps.filter((m) => !m.corrupted).slice(0, 15).map((m) => ({
            id: m.id, time: m.time, trigger: m.trigger, spec: m.spec, label: m.label,
            guard: !!m.guard, manual: !!m.manual,
            files: m.stats?.files ?? null, bytes: m.stats?.bytes ?? null, durationMs: m.stats?.durationMs ?? null,
            complete: m.stats?.complete !== false,
          })),
          corrupted: snaps.filter((m) => m.corrupted).map((m) => m.id),
        }
      }),
      jsonRoute('/dsh-snap/snapshot-now', async () => {
        const k = await loadKernel(store)
        const manifest = k.takeSnapshot({ store, profile, dshHome, trigger: 'manual', label: '面板手动快照' })
        return { ok: true, id: manifest.id, files: manifest.stats.files, durationMs: manifest.stats.durationMs }
      }, { method: 'POST' }),
      jsonRoute('/dsh-snap/doctor', async () => {
        const k = await loadKernel(store)
        return k.doctor(profile, dshHome) // 显式传 dshHome（同 /snap doctor）
      }),
      jsonRoute('/dsh-snap/verify', async () => {
        // G1：校验最新快照完整性（快照侧文件被原地改写=硬链接污染指纹，提前于还原检出）
        const k = await loadKernel(store)
        const newest = k.listSnapshots(store).find((m) => !m.corrupted)
        if (!newest) return { ok: false, code: 'no-snapshot' }
        return k.verifySnapshot(store, newest.id, { deep: false })
      }, { method: 'POST' }),
      jsonRoute('/dsh-snap/open-store', async () => {
        // 打开快照库文件夹（Explorer）；只读操作，无还原面
        spawn('explorer', [store], { detached: true, stdio: 'ignore' })
          .on('error', () => { /* P3-9 */ })
          .unref()
        return { ok: true }
      }, { method: 'POST' }),
    ]
    for (const r of routes) {
      try { const d = server.register(r); if (typeof d === 'function') disposables.push(d) } catch (e) {
        log('warn', `路由注册失败 ${r.path}：${e?.message}`)
      }
    }
    log('info', '面板路由已注册（/dsh-snap/panel 等 5 条）')
  })

  /* ---- dispose：停监视器 + 写净退出标志 + 致命收场捕获 ---- */
  // R4 演练实证两连：① cordis 对 fatal uncaught 直接 exit(1) 不设 process.exitCode；
  // ② 'exit' 事件在该收场路径上也未触发（疑似 reallyExit 绕过）。因此不赌退出机制，
  // 直接挂 uncaughtException 旗标—— fatal 信号在异常抛出瞬间就位。
  // ⚠️ unhandledRejection 不算 fatal：宿主壳有自己的 rejection 处理器时进程会正常退出(0)，
  // 记 fatal 会让下次启动产生假 crash-detected + 假归因链（review #2 实证链）。
  let fatalSeen = 0
  let fatalReason = null
  // B2（0.7.4 审计 P1）：曾挂两个 uncaughtException 监听器（markFatal + rethrowIfSole），
  // `listenerCount <= 1` 永不成立 → 保底重抛死代码；且 HMR 重载泄漏监听器。
  // 单监听器方案：注册前记录外部处理器数；无外部处理器时记录后立即重抛（还原默认 fatal 语义）。
  const externalUncaughtAtBoot = (() => { try { return process.listenerCount('uncaughtException') } catch { return 0 } })()
  const markFatal = (e) => {
    fatalSeen = 1
    fatalReason = String(e?.message || e).slice(0, 140)
    // Node 规约：任何 uncaughtException 监听器存在即抑制默认「打印+退出」。
    // 本插件是唯一处理器（注册时无外部监听器）→ 吞掉异常=宿主带病运行；记录后重抛。
    // 有外部处理器（宿主壳自己的 fail-loud 等）→ 只记录，处置权归宿主。
    if (externalUncaughtAtBoot === 0) {
      try { process.removeListener('uncaughtException', markFatal) } catch { /* 忽略 */ }
      throw e
    }
  }
  try { process.on('uncaughtException', markFatal) } catch { /* 老宿主可容忍 */ }
  const writeFinalState = (code) => {
    try {
      const s = readState(store, profile.name)
      // B1（0.7.4 审计 P1）：HMR 重载时旧实例的 dispose 晚于新实例 apply——旧 dispose 只比
      // pid（同进程）会把**新实例**的 boot 标成净退出，运行闸/崩溃检测随之失效。
      // 终值写入必须 pid+bootId 双匹配：state 已被新实例覆写时旧实例不得再动它。
      if (s && s.pid === process.pid && s.bootId === ownBootId) {
        // exitCode 语义分离：fatal 收场强制非零（cordis 不设 exitCode 的实证），
        // 净退场按真实退出码记录（0 保持 0——曾因 `|| 1` 把正常退出记成致命）
        const realCode = Number(code ?? process.exitCode ?? 0)
        writeJsonAtomic(join(store, `state-${profile.name}.json`), {
          ...s, cleanExit: true, endedAt: Date.now(),
          exitCode: fatalSeen ? (realCode || 1) : realCode,
          fatalReason: fatalSeen ? fatalReason : undefined, // 非零=致命收场（下次启动进归因链）
        })
      }
    } catch { /* 终值写入失败可容忍（未净退出语义兜底） */ }
  }
  const exitListener = (code) => writeFinalState(code)
  try { process.on('exit', exitListener) } catch { /* 老宿主无可容忍 */ }
  if (typeof ctx.effect === 'function') {
    ctx.effect(() => () => {
      for (const d of disposables) { try { d() } catch { /* 忽略 */ } }
      closeCliWatcher()
      clearCliDiffTimer()
      if (cliRetryTimer) { try { clearTimeout(cliRetryTimer) } catch { /* 忽略 */ } }
      try { process.removeListener('uncaughtException', markFatal) } catch { /* 忽略 */ }
      schedDisposed = true
      try { process.removeListener('exit', exitListener) } catch { /* 忽略 */ }
      writeFinalState(process.exitCode)
    }, `${NS}: watcher + clean-exit`)
  }

  log('info', `已挂载：profile=${profile.name} store=${store}${prevUnclean ? '（⚠️ 上次未净退出）' : ''}`)
}
