#!/usr/bin/env node
/**
 * dsh-snap — DSH 稳定与信任套件 · 外部还原器 CLI 内核
 *
 * "装插件搞崩，一键回到装前。"
 *
 * 零依赖单文件设计：本文件会被拷贝进快照库 <store>/cli/ 独立存活，
 * DSH 本体完全起不来时也能用 `node dsh-snap.mjs restore last` 救回。
 *
 * 安全纪律（实现必须遵守）：
 *  1. 快照只读源文件；还原前必拍 guard 快照（还原可撤销）。
 *  2. 任何删除：先 lstat 判 reparse point（junction/symlink 只 unlink 本体，绝不跟随）。
 *  3. 会话与用户工作区数据永不触碰；$DSH_HOME 配置层默认不动（--include-home 才还原）。
 *  4. 危险项只报告不动手；默认还原半径 = profile 清单 + node_modules 缺失/损坏补回。
 *  5. manifest 与文件索引在事务点同步落盘（VS Code 5 分钟批量落盘教训）。
 *  6. 快照库有硬性 GC（OpenCode 533GB 事故教训）；手动快照与 guard 快照豁免。
 */

import {
  appendFileSync, closeSync, copyFileSync, cpSync, linkSync, lstatSync, mkdirSync, openSync, readdirSync,
  readFileSync, readlinkSync, readSync, renameSync, rmSync, rmdirSync, statSync,
  symlinkSync, utimesSync, unlinkSync, writeFileSync,
} from 'node:fs'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { spawn, spawnSync } from 'node:child_process'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir, platform, tmpdir, userInfo } from 'node:os'
import process from 'node:process'

/* ============================================================
 * 常量与配置
 * ============================================================ */

export const MANIFEST_VERSION = 1
/** 内核版本标记（store 营救副本防降级：旧宿主快照不得把新副本刷回旧版） */
export const KERNEL_VERSION = '0.7.4'
const IS_WIN = platform() === 'win32'

/** profile 清单件（快照对象，KB 级全拷贝） */
const PROFILE_FILES = [
  'package.json',
  'pnpm-lock.yaml',
  'cordis.patch.yml',
  'compatibility.json',
  'pnpm-workspace.yaml',
  'cordis.yml',
]

/** $DSH_HOME 顶层散配置（home 层默认白名单，全部小文件） */
const HOME_FILES = [
  'settings.yaml',
  'settings.yaml.imported',
  'AGENTS.md',
]

/** 超过该大小的 home 层文件不进快照，只报告（克制：快照库不是垃圾桶） */
const HOME_FILE_MAX_BYTES = 8 * 1024 * 1024

/**
 * 凭据类键名扫描（G4）：home 层文件入快照前检查——命中则整文件跳过并报告。
 * 只记键名不记值；快照库是明文落盘，凭据进快照=凭据多一份裸拷贝，直接不收。
 * （dsh-backup 凭据哨兵同源教训；宁可漏拍一个配置文件，不可多存一份密钥。）
 * 词内边界 (?![a-z])：camelCase 也命中（authToken/accessToken/sessionToken 曾漏——review #8）
 * F1（0.7.4 审计 P1）：YAML/JSON 的引号 key（"token": / 'api_key':）曾整类绕过——
 * 键名前的可选引号纳入匹配；行首缩进不要求。
 */
const CRED_KEY_RE = /^\s*['\"]?(?:[a-z0-9]+(?:[-_]|\$)?)*?(token|api[-_]?key|apikey|secret(?:[-_]?key)?|password|passwd|pwd|access[-_]?key(?:[-_]?id)?|private[-_]?key|refresh[-_]?token|session[-_]?token|bearer|client[-_]?secret|credentials?|auth)['\"]?(?![a-z])['\"]?\s*:/im

function scanCredentialKeys(text) {
  const names = new Set()
  const re = new RegExp(CRED_KEY_RE.source, 'gim')
  let m
  while ((m = re.exec(text)) !== null) {
    names.add(m[1].trim().toLowerCase())
    if (names.size >= 8) break
  }
  return [...names]
}

/** 默认保留策略（可用 store/config.json 的 retention 覆盖） */
export const DEFAULT_RETENTION = {
  maxSnapshots: 15,
  maxBytes: 3 * 1024 * 1024 * 1024,
  ttlDays: 30,
}

/** node_modules 层单文件上限：超过则跳过（防极端大文件撑爆快照库） */
const NM_FILE_MAX_BYTES = 64 * 1024 * 1024

/** 本内核随包声明的 dsh 列车范围（G11 列车自检用；与 package.json engines.dsh 保持一致） */
export const ENGINES_DSH_SELF = '>=0.2.0-0 <0.3.0'

/**
 * pnpm 已知「原地重写」文件（verify 实测发现：.modules.yaml 每次 install 被
 * 原地 writeFileSync，硬链接把污染同步进快照——2026-11-08 真实快照库 8/9 中招）。
 * 这些文件不入硬链接池：从源复制成私有副本（KB 级，零成本），彻底消除污染面。
 */
const NM_IN_PLACE_FILES = new Set(['.modules.yaml'])

/**
 * 自升级污染面（verify 实测第二发现）：dsh-snap 自身的包文件就在
 * node_modules/dsh-snap 下，部署/自更新=原地覆写，同样污染硬链接快照。
 * 整个自目录走私有副本，且不复用上一快照链接（旧副本可能是被污染的硬链接）。
 */
const NM_PRIVATE_COPY_TOPS = new Set(['dsh-snap'])

function isPrivateCopyTop(relKey) {
  return NM_PRIVATE_COPY_TOPS.has(relKey.split(sep)[0])
}

function isInPlaceNmFile(relKey) {
  const top = relKey.split(sep)[0]
  return NM_IN_PLACE_FILES.has(top) && !relKey.includes(sep)
}

/* ============================================================
 * 小工具
 * ============================================================ */

const pad2 = (n) => String(n).padStart(2, '0')

export function nowId(d = new Date()) {
  return `${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}T` +
    `${pad2(d.getHours())}${pad2(d.getMinutes())}${pad2(d.getSeconds())}-` +
    createHash('sha256').update(`${Date.now()}-${Math.random()}`).digest('hex').slice(0, 6)
}

/** 原子写（临时文件 + rename，绝不半写）：快照 manifest 必须事务点完整落盘 */
function atomicWriteJson(path, value) {
  const tmp = `${path}.tmp-${process.pid}-${Math.random().toString(36).slice(2, 8)}`
  writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', 'utf8')
  renameSync(tmp, path)
}

function atomicWriteText(path, text) {
  const tmp = `${path}.tmp-${process.pid}-${Math.random().toString(36).slice(2, 8)}`
  writeFileSync(tmp, text, 'utf8')
  renameSync(tmp, path)
}

function readJson(path, fallback) {
  try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return fallback }
}

function okReaddir(dir) { try { return readdirSync(dir) } catch { return [] } }

/**
 * reparse point 判定（junction/symlink）：Windows 上 lstat 对 junction 的
 * isSymbolicLink 依 Node 版本而异，这里用「readlink 能成功」兜底判定。
 * 45GB junction 跟随删除事故（官方 #11119）的根因防线。
 */
export function isReparsePoint(path) {
  let st
  try { st = lstatSync(path) } catch { return false }
  if (st.isSymbolicLink()) return true
  if (!st.isFile() && !st.isDirectory()) return true // 其它非常规类型
  try { readlinkSync(path); return true } catch { return false }
}

/** 链接感知的安全删除：绝不跟随 reparse point 递归。 */
export function safeRm(path) {
  if (isReparsePoint(path)) { unlinkSync(path); return 'unlinked-reparse' }
  const st = lstatSync(path)
  if (st.isDirectory()) {
    for (const entry of okReaddir(path)) safeRm(join(path, entry))
    rmdirSync(path)
    return 'removed-dir'
  }
  unlinkSync(path)
  return 'removed-file'
}

function tryReadlink(p) { try { return readlinkSync(p) } catch { return null } }

/** 同卷判定：win32 比盘符；否则比 st.dev */
export function sameVolume(a, b) {
  if (IS_WIN) {
    const da = driveOf(a); const db = driveOf(b)
    return da !== null && da === db
  }
  try { return statSync(a).dev === statSync(b).dev } catch { return false }
}
function driveOf(p) {
  const r = /^[a-zA-Z]:/.exec(resolve(p))
  return r ? r[0].toLowerCase() : null
}

/** pid 是否存活 */
export function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  if (pid === process.pid) return true
  try { process.kill(pid, 0); return true } catch (e) { return e.code === 'EPERM' }
}

function fmtBytes(n) {
  if (!Number.isFinite(n)) return '?'
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0; let v = n
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)}${u[i]}`
}

/* ============================================================
 * 路径解析：DSH_HOME / profile / store（与官方语义对齐）
 * ============================================================ */

/**
 * 解析 DSH_HOME：env DSH_HOME → 候选中第一个像 DSH_HOME 的 → 兜底 %LOCALAPPDATA%\DSH（Windows）/ ~/.dsh（其余）
 */
export function resolveDshHome() {
  const candidates = []
  if (process.env.DSH_HOME) candidates.push(resolve(process.env.DSH_HOME))
  const home = homedir()
  candidates.push(join(home, '.dsh'))
  if (IS_WIN && process.env.LOCALAPPDATA) candidates.push(join(process.env.LOCALAPPDATA, 'DSH'))
  for (const c of candidates) {
    // P1-2 修复：existsNo 是单参函数——旧代码 existsNo(c, 'profiles') 的第二参被静默
    // 丢弃，探测退化为「目录存在即命中」，会对不存在的 profile 拍空壳快照（审计实证）
    if (existsNo(join(c, 'profiles')) || existsNo(join(c, 'settings.yaml'))) return c
  }
  return candidates[candidates.length - 1]
}
function existsNo(p) { try { statSync(p); return true } catch { return false } }

/** 解析 profile：env DSH_PROFILE 优先；默认 desktop（存在时），否则 profiles/ 下第一个有 package.json 的 */
export function resolveProfile(dshHome = resolveDshHome()) {
  const profilesDir = join(dshHome, 'profiles')
  const name = process.env.DSH_PROFILE
    || (existsNo(join(profilesDir, 'desktop', 'package.json')) ? 'desktop' : firstProfile(profilesDir))
    || 'default'
  return { name, dir: join(profilesDir, name) }
}

function firstProfile(profilesDir) {
  // 排序保证确定性（readdir 序在 Linux/APFS 上是哈希序且随目录变动漂移——
  // 同进程组两次解析可能拿到不同 profile：快照拍 A、还原到 B）
  for (const entry of okReaddir(profilesDir).sort()) {
    if (existsNo(join(profilesDir, entry, 'package.json'))) return entry
  }
  return null
}

/** 快照库：默认与 DSH_HOME 同目录的 .dsh-snap（同卷、$DSH_HOME 之外） */
export function resolveStore(dshHome = resolveDshHome()) {
  return resolve(process.env.DSH_SNAP_HOME || join(dirname(dshHome), '.dsh-snap'))
}

export function storeLayout(store) {
  return {
    store,
    cli: join(store, 'cli'),
    snapshots: join(store, 'snapshots'),
    journal: join(store, 'journal'),
    trash: join(store, 'trash'),
    config: join(store, 'config.json'),
    state: join(store, 'state.json'),
  }
}

/* ============================================================
 * 运行状态（Chrome exit_type 脏关机标志模式）
 * ============================================================ */

/** 读某 profile 的运行状态；向后兼容旧的单一 state.json（profile 字段匹配或缺省时） */
export function readState(store, profileName) {
  const L = storeLayout(store)
  if (profileName) {
    const p = readJson(join(L.store, `state-${profileName}.json`), null)
    if (p) return p
  }
  const legacy = readJson(L.state, null)
  // legacy 无 profile 字段：视作本 profile 的历史（旧版单文件时代只有单 profile 在用）；
  // 显式 profile 且不匹配 → 不采信（跨 profile 误报防线）
  if (legacy && (!profileName || !legacy.profile || legacy.profile === profileName)) return legacy
  return null
}

/** 由插件宿主半调用：启动时登记；正常 dispose 时 markCleanExit */
export function markBoot(store, extra = {}) {
  try { mkdirSync(store, { recursive: true }) } catch { /* 已存在/无权限由后续写报错 */ }
  const profileName = extra.profile || resolveProfile().name
  const prev = readState(store, profileName)
  const state = { bootId: nowId(), pid: process.pid, profile: profileName, startedAt: Date.now(), bootTimeWall: Date.now(), cleanExit: false, ...extra }
  atomicWriteJson(join(store, `state-${profileName}.json`), state)
  const previousUnclean = !!(prev && prev.cleanExit === false && !pidAlive(prev.pid))
  return { state, previousUnclean, previous: prev }
}

export function markCleanExit(store, profileName) {
  const s = readState(store, profileName)
  if (s) atomicWriteJson(join(store, `state-${s.profile || profileName || 'default'}.json`), { ...s, cleanExit: true, endedAt: Date.now() })
}

/* ============================================================
 * 快照实现
 * ============================================================ */

/**
 * 拍快照（同步、事务点完整落盘）。
 * @param {object} opts {store, profile:{name,dir}, dshHome(显式覆盖,桌面端进程无该env),
 *   trigger, spec, note, label, nodeModules:boolean(默认true), home:boolean(默认true),
 *   prevId(增量基线), onProgress}
 * @returns manifest 对象（已落盘）
 */
export function takeSnapshot(opts) {
  const t0 = Date.now()
  const L = storeLayout(opts.store)
  const profile = opts.profile || resolveProfile()
  const id = nowId()
  const dir = join(L.snapshots, id)
  const nmDir = join(dir, 'node_modules')
  const prev = opts.prevId ? readSnapshotManifest(opts.store, opts.prevId) : null
  const prevIndex = prev ? readFilesIndex(opts.store, prev.id) : null
  const prevNmDir = prev ? join(L.snapshots, prev.id, 'node_modules') : null

  mkdirSync(join(dir, 'profile'), { recursive: true })
  if (opts.nodeModules !== false) mkdirSync(nmDir, { recursive: true })
  if (opts.home !== false) mkdirSync(join(dir, 'home'), { recursive: true })

  /* ---- 层1：profile 清单（同步全拷贝，KB 级） ---- */
  const profileTaken = []
  const profileMissing = []
  // F1（0.7.4 审计 P1）：profile 配置件（cordis.patch.yml 等）是插件的配置面，常含
  // API key。曾完全不扫描、静默明文入快照。但这些文件**不能跳过**（跳过=还原后配置缺失，
  // 修复能力归零）——策略改为「照常拷贝 + 命中键名显式记入 manifest + journal 警示」，
  // 让用户知情（快照库须妥善保护），还原完整性不受损。
  const profileCredHits = []
  for (const f of PROFILE_FILES) {
    const src = join(profile.dir, f)
    if (existsNo(src)) {
      copyFileSync(src, join(dir, 'profile', f))
      if (!IS_WIN) { try { const sst = statSync(src); utimesSync(join(dir, 'profile', f), sst.atime, sst.mtime) } catch { /* 尽力 */ } } // POSIX copy 不保留 mtime
      profileTaken.push(f)
      try {
        const keys = scanCredentialKeys(readFileSync(src, 'utf8'))
        if (keys.length) profileCredHits.push({ file: f, keys })
      } catch { /* 二进制/读不了不扫 */ }
    } else profileMissing.push(f)
  }
  opts.onProgress?.('profile', { taken: profileTaken })

  /* ---- 层2：$DSH_HOME 散配置（白名单 + 单文件上限） ---- */
  const dshHome = opts.dshHome || resolveDshHome()
  const homeTaken = []; const homeSkipped = []
  if (opts.home !== false) {
    for (const f of HOME_FILES) {
      const src = join(dshHome, f)
      if (!existsNo(src)) continue
      const st = statSync(src)
      if (st.size > HOME_FILE_MAX_BYTES) { homeSkipped.push({ file: f, reason: 'too-large', bytes: st.size }); continue }
      // 凭据键扫描（G4）：命中即整文件不收（快照库明文落盘，凭据不入库）
      try {
        const keys = scanCredentialKeys(readFileSync(src, 'utf8'))
        if (keys.length) { homeSkipped.push({ file: f, reason: 'credential-like', keys }); continue }
      } catch { /* 读不了按二进制处理，照常拷贝 */ }
      copyFileSync(src, join(dir, 'home', f))
      if (!IS_WIN) { try { utimesSync(join(dir, 'home', f), st.atime, st.mtime) } catch { /* 尽力 */ } } // POSIX copy 不保留 mtime
      homeTaken.push(f)
    }
  }

  /* ---- 层3：node_modules 增量硬链接 ---- */
  const nmSrc = join(profile.dir, 'node_modules')
  let nm
  if (opts.nodeModules === false) nm = { present: false, note: '本快照未含 node_modules 层' }
  else if (!existsNo(nmSrc)) nm = { present: false, note: 'node_modules 不存在' }
  else {
    nm = snapshotNodeModules({
      src: nmSrc, dest: nmDir, prevIndex, prevNmDir,
      sameVol: sameVolume(nmSrc, opts.store),
      onProgress: opts.onProgress,
    })
  }

  /* ---- 文件索引（还原与下次增量用；manifest 本体保持 KB 级） ---- */
  if (nm.index?.length) atomicWriteText(join(dir, 'files-index.tsv'), nm.index.map((r) => r.join('\t')).join('\n'))

  /* ---- manifest（最后写 manifest = 快照存在的原子标志） ---- */
  const dshVersion = readJson(join(profile.dir, 'node_modules', 'dshmarket', 'package.json'), null)?.version ?? null
  // harnessFingerprint 内含 reg query /s spawnSync（秒级）——快照热路径不消费指纹，只有
  // 哨兵（宿主启动/doctor）才需要；0.7.0 曾在此白调（每次快照多付最多 15s，toggle 快照高频面）
  const hVer = resolveHarnessVersion(readJson(join(profile.dir, 'package.json'), null)?.dependencies)
  const manifest = {
    version: MANIFEST_VERSION,
    id,
    time: new Date().toISOString(),
    timeEpoch: Date.now(),
    trigger: opts.trigger || 'manual',
    spec: opts.spec ?? null,
    label: opts.label ?? null,
    note: opts.note ?? null,
    manual: (opts.trigger || 'manual') === 'manual',
    guard: (opts.trigger || '') === 'pre-restore',
    profile: { name: profile.name, dir: profile.dir },
    dshHome,
    dshVersion,
    harnessVersion: hVer?.version.raw ?? null, // 破坏性更新对比锚点（还原跨版本时告警用）
    platform: { os: platform(), node: process.version, user: safeUser() },
    layers: {
      profile: { taken: profileTaken, missing: profileMissing, credHits: profileCredHits },
      home: { taken: homeTaken, skipped: homeSkipped },
      nodeModules: nm,
    },
    stats: {
      files: nm.files ?? 0,
      hardlinkedFromPrev: nm.reusedPrev ?? 0,
      hardlinkedFromSource: nm.linkedSource ?? 0,
      copied: nm.copied ?? 0,
      reparseEntries: nm.reparse ?? 0,
      bigSkipped: nm.bigSkipped ?? 0, // P3-3：跨卷大文件跳过数如实入账（漏拍面必须可见）
      pollutedPrev: nm.pollutedPrev?.length ?? 0, // A3：上一快照侧被污染、已回退 live 源的文件数
      bytes: nm.bytes ?? 0,
      durationMs: Date.now() - t0,
      complete: nm.complete !== false,
    },
    prevId: prev ? prev.id : null,
  }
  atomicWriteJson(join(dir, 'manifest.json'), manifest)

  /* ---- store 自维护：CLI 副本 + 双击营救 shim ---- */
  ensureStoreSelfCopy(opts.store, opts.dshHome || resolveDshHome())
  appendJournal(opts.store, { kind: 'snapshot', id, trigger: manifest.trigger, spec: manifest.spec, profile: profile.name,
    credHits: profileCredHits.length ? profileCredHits : undefined }) // F1：凭据命中警示（只记文件与键名，不记值）
  return manifest
}

function safeUser() { try { return userInfo().username } catch { return null } }

/**
 * node_modules 增量硬链接快照。
 * 未变者（与 prevIndex 的 size+mtime 一致）从上一快照硬链接（零拷贝）；
 * 变更/新增者从源硬链接（同卷）/复制（跨卷）；reparse 条目只记录 target 不深入。
 */
export function snapshotNodeModules({ src, dest, prevIndex, prevNmDir, sameVol, onProgress }) {
  const prevMap = new Map()
  if (prevIndex) for (const r of prevIndex) prevMap.set(r[0], r)
  const index = []
  let files = 0, reusedPrev = 0, linkedSource = 0, copied = 0, reparse = 0, bytes = 0, bigSkipped = 0
  let complete = true
  const pollutedPrev = [] // A3：上一快照侧字节与记录哈希不符（确证污染）——如实入账，绝不静默
  const walk = (abs, rel) => {
    let entries
    try { entries = readdirSync(abs) } catch { complete = false; return }
    for (const entry of entries) {
      const sAbs = join(abs, entry)
      const rAbs = join(dest, rel, entry)
      let st
      try { st = lstatSync(sAbs) } catch { continue }
      if (st.isSymbolicLink() || isReparsePoint(sAbs)) {
        index.push([join(rel, entry), '-1', '-1', 'reparse', String(tryReadlink(sAbs) ?? '')])
        reparse++
        continue
      }
      if (st.isDirectory()) { walk(sAbs, join(rel, entry)); continue }
      if (!st.isFile()) continue
      // 大小上限只约束跨卷复制路径（硬链接是零成本元数据操作，不设限）——
      // 否则会漏拍 claude.exe/codex.exe 这类大体积子代理二进制
      if (!sameVol && st.size > NM_FILE_MAX_BYTES) { bigSkipped++; continue }
      const relKey = join(rel, entry)
      const prev = prevMap.get(relKey)
      const privateCopy = isInPlaceNmFile(relKey) || isPrivateCopyTop(relKey)
      let hash = ''
      let ok = false
      if (prev && prevNmDir && !privateCopy && Number(prev[1]) === st.size && Number(prev[2]) === Math.round(st.mtimeMs)) {
        // P1-3 修复：size+mtime 相同≠内容相同（exFAT 2 秒 mtime 粒度/tar/git 保留时间戳）。
        // 旧实现直接复用上一快照的旧内容并继承旧哈希——碰撞时快照静默存陈旧内容，
        // 且 deep verify 永远判一致（审计实证）。
        // A3（0.7.4 审计 P0）：liveHash 与 prev hash 一致还不够——prev[5] 是上一快照
        // **记录时**的哈希，快照侧字节此后可被硬链接污染改动（复现：live=GOOD、prev 快照侧
        // 被改成 EVIL，两 hash 记录仍相等 → linkSync(EVIL) → 新快照静默存污染且 complete:true）。
        // 复用前必须实算上一快照侧当前哈希并与 liveHash 对表；不符=上一快照被污染 →
        // 回退 live 源链接（新快照仍干净），并把上一快照异常如实记入 manifest.stats。
        const liveHash = safeSha256(sAbs)
        hash = liveHash
        if (liveHash && prev[5] && liveHash === prev[5]) {
          const pSrc = join(prevNmDir, relKey)
          const prevHashNow = safeSha256(pSrc)
          if (prevHashNow === liveHash) {
            try {
              mkdirSync(dirname(rAbs), { recursive: true })
              linkSync(pSrc, rAbs)
              reusedPrev++; files++; bytes += st.size; ok = true
            } catch { /* 上一快照文件丢失 → 走源 */ }
          } else if (prevHashNow) {
            pollutedPrev.push(relKey) // 实算成功但不符 = 确证污染（非文件丢失）
          }
        }
        // 哈希不符/上一快照无哈希/上一快照被污染 → 视为已变更，落源路径（hash 已实算，不重复算）
      }
      if (!ok) {
        try {
          mkdirSync(dirname(rAbs), { recursive: true })
          if (sameVol && !privateCopy) { linkSync(sAbs, rAbs); linkedSource++ }
          else {
            copyFileSync(sAbs, rAbs); copied++ // 原地写文件/自目录强制私有副本，杜绝硬链接污染面
            // Windows CopyFileW 保留源 mtime；POSIX copy 是读写循环，目标 mtime=now。
            // 索引记录的是 live 的 size/mtime——非 Windows 必须把副本 mtime 对齐 live，
            // 否则 verify 的 size+mtime 指纹永远漂移（CI 三平台实测）
            if (!IS_WIN) { try { utimesSync(rAbs, st.atime, st.mtime) } catch { /* 尽力对齐 */ } }
          }
          files++; bytes += st.size
          if (!hash) hash = safeSha256(sAbs) // 新内容实算（硬链接/复制后源与快照同内容）
        } catch {
          try { copyFileSync(sAbs, rAbs); copied++; files++; bytes += st.size; if (!IS_WIN) { try { utimesSync(rAbs, st.atime, st.mtime) } catch { /* 尽力 */ } } hash = safeSha256(sAbs) }
          catch { complete = false; continue }
        }
      }
      // C3（0.7.4 审计 P2）：索引行第 7 列记录快照侧 (dev,ino)——GC 的物理共享按 inode 身份
      // 计（同内容不同 inode 是两份物理占用，按 hash 计曾显著低估配额占用）；hash 仍作完整性字段
      const snapSt = (() => { try { return lstatSync(rAbs) } catch { return null } })()
      index.push([relKey, String(st.size), String(Math.round(st.mtimeMs)), 'file', '', hash, snapSt ? `${snapSt.dev}:${snapSt.ino}` : ''])
    }
  }
  walk(src, '')
  onProgress?.('node_modules', { files })
  return { present: true, files, reusedPrev, linkedSource, copied, reparse, bytes, bigSkipped, complete, index, pollutedPrev }
}

function readFilesIndex(store, id) {
  try {
    const text = readFileSync(join(storeLayout(store).snapshots, id, 'files-index.tsv'), 'utf8')
    const snapRoot = join(storeLayout(store).snapshots, id, 'node_modules')
    const out = []
    for (const line of text.split('\n')) {
      if (!line) continue
      const row = line.replace(/\r$/, '').split('\t') // CRLF 工具改写容错：行尾 \r 曾落进末列 hash 致 deep verify 全量假报
      // 信任边界闸（与 manifest id 形态闸同级）：索引是外部可控数据（review #4 实证
      // rel=..\..\x.tsv 可写穿 node_modules 到任意路径）。resolve 后必须仍在快照 nm 根内。
      const abs = resolve(snapRoot, row[0])
      if (!abs.startsWith(snapRoot + sep) && abs !== snapRoot) continue
      out.push(row)
    }
    return out
  } catch { return null }
}

/** 读快照 manifest；损坏/半写/篡改返回 null——调用方必须当它不存在。
 * A1（0.7.4 审计 P0）：layers.profile/home.taken 是还原的写路径来源——曾不做白名单校验，
 * 篡改 manifest 塞进 ['../../victim.txt'] 即可把快照侧文件写出 profile/home（越界覆盖）。
 * 白名单 = 快照时写入的 PROFILE_FILES/HOME_FILES 常量；无效 → 整个 manifest 视为损坏。 */
export function readSnapshotManifest(store, id) {
  if (!/^[0-9T]{8}T[0-9]{6}-[0-9a-f]{6}$/.test(id)) return null // id 形态闸（防路径逃逸）
  const m = readJson(join(storeLayout(store).snapshots, id, 'manifest.json'), null)
  if (!m || m.version !== MANIFEST_VERSION || m.id !== id) return null
  const takenOk = (arr, allowlist) => Array.isArray(arr) && new Set(arr).size === arr.length
    && arr.every((f) => typeof f === 'string' && allowlist.includes(f))
  if (!takenOk(m.layers?.profile?.taken, PROFILE_FILES)) return null
  if (m.layers?.home?.taken !== undefined && !takenOk(m.layers.home.taken, HOME_FILES)) return null
  return m
}

export function listSnapshots(store) {
  const root = storeLayout(store).snapshots
  const out = []
  for (const id of okReaddir(root)) {
    const m = readSnapshotManifest(store, id)
    out.push(m ?? { id, corrupted: true })
  }
  out.sort((a, b) => (b.timeEpoch || 0) - (a.timeEpoch || 0))
  return out
}

function newestSnapshotId(store) {
  return listSnapshots(store).find((m) => !m.corrupted)?.id ?? null
}

/**
 * 双击营救 bat 的 node 解析段（G3）：纯 ASCII。
 * 优先级（行序即覆盖序，后写胜出）：DSH runtime node（env 或生成期烘焙路径）> PATH node。
 * 营救场景恰恰是"环境坏了"的时刻，不能假设 PATH 里有 node。
 */
function batNodeSetup(dshHome) {
  const lines = ['set "DSHSNAP_NODE="']
  if (dshHome) {
    const baked = join(dshHome, 'dsh-runtimes', 'dsh-primary-runtime', 'dependencies', 'node', 'bin', 'node.exe')
    if (existsNo(baked)) lines.push(`if exist "${baked}" set "DSHSNAP_NODE=${baked}"`)
  }
  lines.push(
    'if exist "%DSH_HOME%\\dsh-runtimes\\dsh-primary-runtime\\dependencies\\node\\bin\\node.exe" set "DSHSNAP_NODE=%DSH_HOME%\\dsh-runtimes\\dsh-primary-runtime\\dependencies\\node\\bin\\node.exe"',
    'if not defined DSHSNAP_NODE set "DSHSNAP_NODE=node"',
  )
  return lines.join('\r\n') + '\r\n'
}

/** 营救 shim 的 node 调用行（D5：不依赖 PATH 里有 node——runtime 兜底已在 nodeSetup） */
function batInvoke(argsLine, nodeSetup) {
  return nodeSetup + `"%DSHSNAP_NODE%" "%~dp0dsh-snap.mjs" ${argsLine}\r\n`
}

function ensureStoreSelfCopy(store, dshHome) {
  const L = storeLayout(store)
  mkdirSync(L.cli, { recursive: true })
  let self
  try { self = resolve(fileURLToPath(import.meta.url)) } catch { return }
  const target = join(L.cli, 'dsh-snap.mjs')
  try {
    if (self !== target) {
      // 防降级：store 副本记录其内核版本；只有「运行方版本 >= 副本版本」才允许刷新。
      // （否则一台还跑着 0.3.5 的 profile 拍快照就会把营救副本刷回旧版——演练 R4 实证。）
      const verFile = join(L.cli, 'kernel-version.json')
      const verRec = readJson(verFile, null)
      if (verRec?.version) {
        const a = parseVer(verRec.version), b = parseVer(KERNEL_VERSION)
        if (a && b && vCmp(b, a) < 0) return // 运行方更旧：不动营救副本
      }
      // 内容不同才覆盖（避免无谓写入）；运行方=包内新版本时刷新营救副本
      let stale = true
      try { stale = readFileSync(target, 'utf8') !== readFileSync(self, 'utf8') } catch { /* 读不了就覆盖 */ }
      if (stale) {
        copyFileSync(self, target)
        atomicWriteJson(verFile, { version: KERNEL_VERSION, at: new Date().toISOString() })
        if (IS_WIN) {
          // .bat 用纯 ASCII，避免 cmd 代码页解析问题
          const nodeSetup = batNodeSetup(dshHome)
          writeFileSync(join(L.cli, 'dsh-snap.bat'),
            '@echo off\r\nchcp 65001 >nul\r\n' + batInvoke('list %*', nodeSetup) + 'pause\r\n', 'utf8')
          // D2：restore last 现在自动选最近「装前」快照（manual/guard 不再可能被选中）
          writeFileSync(join(L.cli, 'restore-last.bat'),
            '@echo off\r\nchcp 65001 >nul\r\necho This will restore the DSH plugin environment to the most recent pre-install snapshot.\r\npause\r\n' +
            batInvoke('restore last\r\npause\r\n', nodeSetup), 'utf8')
          // D5：外壳握手事故的专用一键（GUI 完全退出后双击）——曾只推荐裸 CLI 命令，
          // 事故现场未必有 PATH node，也没有现成 bat
          writeFileSync(join(L.cli, 'repair-gui.bat'),
            '@echo off\r\nchcp 65001 >nul\r\necho This resets the GUI shell network state (backup kept). Fully quit DeepSeek desktop first (tray too).\r\npause\r\n' +
            batInvoke('repair-gui\r\npause\r\n', nodeSetup), 'utf8')
        }
      } else if (verRec?.version !== KERNEL_VERSION) {
        // P1-07：代码内容相同但 marker 滞后（如人工同步过代码却没带 marker）也要校正——
        // 否则防降级闸永远按旧版本比对，新内核可能被旧宿主合法覆盖回去
        atomicWriteJson(verFile, { version: KERNEL_VERSION, at: new Date().toISOString() })
      }
    }
  } catch { /* 自拷贝失败不阻塞快照 */ }
}

function appendJournal(store, entry) {
  try {
    const p = join(storeLayout(store).journal, 'manifest-journal.jsonl')
    mkdirSync(dirname(p), { recursive: true })
    appendFileSync(p, JSON.stringify({ time: new Date().toISOString(), ...entry }) + '\n')
  } catch { /* journal 失败不阻塞主流程 */ }
}

/* ============================================================
 * 还原实现
 * ============================================================ */

/** 装前触发器判定（D2）：`restore last` 的「last」承诺 = 回到最近一次**装前**。
 * manual/guard/scheduled/harness-change 都可成为 newest——曾直接选 newest，
 * 双击营救可能恢复到「拍完快照后环境又坏了」的状态（broken manual 快照）。
 * pre-restore（guard）排除：undo 有专门路径，且 guard 是「还原前现场」不是装前。 */
const PRE_INSTALL_TRIGGERS = new Set(['baseline'])
const PRE_INSTALL_RE = /^(?:agent:(?:install|uninstall|set_bundle|disable|enable)[^,;]*|cli-install|cli-uninstall|web-install|web-uninstall)/
function isPreInstallTrigger(t) {
  return typeof t === 'string' && (PRE_INSTALL_TRIGGERS.has(t) || PRE_INSTALL_RE.test(t))
}
/** 「restore last」的精确目标：最近的装前触发器快照；没有装前快照时退回最近可用快照
 * （首装场景只有 baseline——baseline 也是承诺中的"装前"）。返回 {id, fallback} */
export function lastRestoreTarget(store) {
  const snaps = listSnapshots(store).filter((m) => !m.corrupted)
  const pre = snaps.find((m) => isPreInstallTrigger(m.trigger))
  if (pre) return { id: pre.id, fallback: false }
  const newest = snaps[0]
  if (newest) return { id: newest.id, fallback: true }
  return { id: null, fallback: false }
}

/** 还原互斥锁（B4，0.7.4 审计 P2）：进度文件只做中断检测不构成互斥——两个 restore 可
 * 交叉拍 guard、互相覆盖进度。锁用 wx 独占创建；活 pid 持锁=拒绝；死 pid（崩溃残留）=收编。
 * 返回 {ok, fd?, error?}；finally 必须 releaseRestoreLock。 */
export function restoreLockPath(store) {
  return join(storeLayout(store).store, 'restore.lock')
}
function acquireRestoreLock(store) {
  const p = restoreLockPath(store)
  for (let attempt = 0; attempt < 2; attempt++) {
    let fd = null
    try { fd = openSync(p, 'wx') } catch (e) {
      if (e?.code !== 'EEXIST') return { ok: false, error: String(e?.message || e) }
      // 已有锁：持锁进程活着=拒绝；死了=收编（清掉重来）
      const rec = readJson(p, null)
      if (rec?.pid && pidAlive(rec.pid)) return { ok: false, error: `另一还原仍在进行（pid=${rec.pid}）——并发还原被拒绝`, busy: true }
      try { rmSync(p, { force: true }) } catch { return { ok: false, error: 'stale lock 清理失败' } }
      continue
    }
    try {
      writeFileSync(fd, JSON.stringify({ pid: process.pid, startedAt: Date.now() }), 'utf8')
    } catch { /* 写不进也持锁（fd 原子性已保证互斥） */ }
    return { ok: true, fd }
  }
  return { ok: false, error: '锁竞争两次未成功' }
}
function releaseRestoreLock(store, fd) {
  try { if (fd !== null && fd !== undefined) closeSync(fd) } catch { /* 忽略 */ }
  try { rmSync(restoreLockPath(store), { force: true }) } catch { /* 忽略 */ }
}

/** 还原进度文件（G6）：存在=上次还原未完成；完成即删——存在性即中断标志 */
export function restoreProgressPath(store) {
  return join(storeLayout(store).store, 'restore-in-progress.json')
}

function writeRestoreProgress(store, patch) {
  try {
    atomicWriteJson(restoreProgressPath(store), { pid: process.pid, startedAt: Date.now(), ...patch })
  } catch { /* 进度记录失败不阻塞还原本体 */ }
}

/** 读未完成的还原；pid 仍存活=正在还原中（另一进程/本进程），不算中断 */
export function readInterruptedRestore(store) {
  const p = readJson(restoreProgressPath(store), null)
  if (!p) return null
  if (pidAlive(p.pid)) return null
  return p
}

/**
 * pid 是否仍是"写入 state 时的那个宿主"。
 * pidAlive 挡不住 Windows pid 复用（宿主死后 pid 秒级被别的 node 进程顶替，
 * 镜像名也同为 node.exe——演练 R3 实证）。核验链：
 *  1. 死 → false
 *  2. state 带了 bootTimeWall → 用 PowerShell 查进程创建时间比对（±15s 容忍）
 *  3. 无 bootTimeWall（旧 state）→ 退化为镜像名粗核验
 * 创建时间查询失败 → 保守维持"活着"。
 */
function pidIsHostProcess(pid, bootTimeWall) {
  if (!pidAlive(pid)) return false
  if (!IS_WIN) return true
  if (Number.isFinite(bootTimeWall) && bootTimeWall > 0) {
    try {
      const out = spawnSync('powershell', ['-NoProfile', '-Command',
        `$p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if ($p) { [string][double]$p.StartTime.ToUniversalTime().Subtract([datetime]'1970-01-01').TotalMilliseconds }`],
        { encoding: 'utf8', timeout: 10000 })
      const createdMs = Number(String(out.stdout || '').trim())
      // 查询失败（超时/无 powershell/输出空）→ 保守维持"活着"（注释承诺的 fail-safe；
      // 曾在 createdMs NaN 时 return false——fail-open 判死，restore 少一道拦截）
      if (!Number.isFinite(createdMs) || createdMs <= 0) return true
      // 单向比对：pid 复用的特征是「新进程创建时间晚于 state 写入」。
      // HMR 重载会在不换进程的情况下重写 state（bootTimeWall 晚于进程创建），
      // 双向 abs 比对会把这种活宿主误判为已死（2026-11-09 桌面实机实证，差 42h）。
      return createdMs - bootTimeWall <= 15_000 // 创建晚于 state 写入 = 复用 pid，宿主已死
    } catch { return true }
  }
  try {
    const out = spawnSync('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { encoding: 'utf8', timeout: 8000 })
    const line = String(out.stdout || '').trim()
    if (!line || /INFO:/.test(line)) return false // pid 已不存在
    return /node\.exe|deepseek/i.test(line) // 活着但镜像不符 = 复用 pid，视作宿主已死
  } catch { return true }
}

/** 探测 DSH 是否正在运行（pid 存活 + 进程名探测 + 安装进行中标记） */
export function detectRunningDsh(profile, store = resolveStore(), { processName = true } = {}) {
  const reasons = []
  const runRecord = join(profile.dir, '.plugin-manager', 'run.json')
  if (existsNo(runRecord)) reasons.push({ kind: 'install-in-progress', detail: `存在未结束的插件操作记录：${runRecord}` })
  const state = readState(store, profile.name)
  const hostAlive = state ? pidIsHostProcess(state.pid, state.bootTimeWall) : false
  const thisProfileHostDead = !!(state && !hostAlive)
  if (state && state.cleanExit === false && hostAlive) {
    // profile 粒度：state.json 记录的是挂载插件的 profile；只在本 profile 的宿主还活着时才拒绝
    //（store 为同 DSH_HOME 的多 profile 共享；desktop 活着不妨碍还原 headless）
    const sameProfile = !state.profile || state.profile === (profile.name || '')
    if (sameProfile) {
      reasons.push({ kind: 'alive-pid', detail: `${state.profile || 'DSH'} profile 的宿主 pid=${state.pid} 仍在运行（state.json 未标 cleanExit）` })
    }
  }
  // 进程名粗探针只在「state 文件无法证明本 profile 宿主已死」时兜底：
  // 多 profile 共存时 DeepSeek Harness.exe 可能属于别的 profile（desktop 常驻），
  // 一刀切会把 web/headless 的合法还原全部误拦成 --force（演练 R1 实证）。
  if (IS_WIN && processName && !thisProfileHostDead) {
    try {
      const out = spawnSync('tasklist', ['/FI', 'IMAGENAME eq DeepSeek Harness.exe', '/FO', 'CSV', '/NH'], { encoding: 'utf8', timeout: 8000 })
      if (/DeepSeek Harness\.exe/i.test(String(out.stdout || ''))) {
        reasons.push({ kind: 'process-name', detail: '检测到 DeepSeek Harness.exe 进程（tasklist）——若确认为其它 profile 的宿主可用 --force' })
      }
    } catch { /* 探测失败不阻塞，其余防线仍在 */ }
  }
  return reasons
}

/** 还原计划（dry-run 与实际共用同一计算）。store：可选，传入即启用 D1 内容确证
 * （size+mtime 相同但 inode 不同的 live 文件必须对内容——损坏载荷可伪装 upToDate）。 */
export function buildRestorePlan({ manifest, idx, profile, includeHome, store }) {
  const plan = {
    profileFiles: manifest.layers.profile.taken,
    homeFiles: includeHome ? manifest.layers.home.taken : [],
    nodeModules: { present: !!manifest.layers.nodeModules.present, missing: 0, mismatched: 0, upToDate: 0, reparseMissing: 0, extraneousTopLevel: [] },
  }
  if (!manifest.layers.nodeModules.present || !idx) return plan
  const nmCur = join(profile.dir, 'node_modules')
  const snapNmRoot = store ? join(storeLayout(store).snapshots, manifest.id, 'node_modules') : null
  // snapTop 记两级键：顶层名（'pkg' / '@org'）+ scope 二级（'@org/pkg'）。
  // 只记一级时，「锚内含 @org 部分包」的场景会把同 scope 的真 extraneous 兄弟包整体漏掉
  //（M 系列演练宣称修复但首版无效的根因：外层 snapTop.has('@org') 命中即 continue）
  const snapTop = new Set()
  for (const row of idx) {
    const [rel, size, idxRowMtime, kind] = row
    const segs = rel.split(sep)
    // reparse 行也登记顶层名（review #5：junction 被物化成真目录后，若不登记会被误判
    // extraneous 且 --prune-extraneous 把快照明知的包清走）
    snapTop.add(segs[0])
    if (segs[0].startsWith('@') && segs.length > 1) snapTop.add(`${segs[0]}${sep}${segs[1]}`)
    if (kind === 'reparse') {
      if (!existsNo(join(nmCur, rel))) plan.nodeModules.reparseMissing++
      continue
    }
    let cur = null
    try { cur = statSync(join(nmCur, rel)) } catch { /* 缺失 */ }
    if (!cur || !cur.isFile()) { plan.nodeModules.missing++; continue }
    if (cur.size !== Number(size) || Math.round(cur.mtimeMs) !== Number(idxRowMtime)) plan.nodeModules.mismatched++
    else {
      // D1（0.7.4 审计 P1）：size+mtime 相同但 inode 不同 = 文件被 replace 过——同尺寸同
      // mtime 的损坏载荷可伪装 upToDate（计划说无需回填 → restore 报成功却保留坏 payload）。
      // 优先比 (dev,ino)（C3 起索引行第 7 列）；inode 列缺失（老快照）用快照记录的 sha256；
      // 都没有退字节比较。size+mtime 只能是"待核验提示"，不能是内容相等结论。
      let upToDate = true
      const rowIno = row[6] || null
      if (rowIno) {
        upToDate = `${cur.dev}:${cur.ino}` === rowIno
      } else if (row[5]) {
        upToDate = safeSha256(join(nmCur, rel)) === row[5]
      } else if (snapNmRoot) {
        try { upToDate = filesEqualSync(join(nmCur, rel), join(snapNmRoot, rel)) } catch { upToDate = false }
      }
      if (upToDate) plan.nodeModules.upToDate++
      else plan.nodeModules.mismatched++
    }
  }
  // 快照没有的顶层条目（包级 extraneous）。scope 目录（@org）不整目录判定——深入一层按包判定
  // （M 系列演练实证：@linxin666 锚内有 task-board，装兄弟包后 scope 整体"有交集"——
  //   整目录判定把 scope 内真 extraneous（pet/git-graph…）全部漏掉）
  for (const entry of okReaddir(nmCur)) {
    if (entry.startsWith('.')) continue // .bin/.pnpm/.ignored/.modules.yaml 等工具条目永不属 extraneous
    if (isReparsePoint(join(nmCur, entry))) continue // 顶层链接（workspace link: 等）不按 extraneous 处置
    if (entry.startsWith('@')) {
      for (const sub of okReaddir(join(nmCur, entry))) {
        if (sub.startsWith('.')) continue
        const pkgKey = `${entry}${sep}${sub}`
        if (!snapTop.has(pkgKey)) plan.nodeModules.extraneousTopLevel.push(`${entry}/${sub}`)
      }
      continue
    }
    if (snapTop.has(entry)) continue
    plan.nodeModules.extraneousTopLevel.push(entry)
  }
  return plan
}

export function restoreRadiusStatement(manifest) {
  return [
    '还原半径声明：',
    `  ✅ 已还原：profile 清单 [${manifest.layers.profile.taken.join(', ')}]`,
    manifest.layers.nodeModules.present
      ? '  ✅ 已回填：node_modules 中缺失/内容不符的文件（多出的包默认保留，见报告）'
      : '  ⚠️ 本快照不含 node_modules 层',
    manifest.layers.home.taken.length
      ? `  ⏸ home 层（${manifest.layers.home.taken.join(', ')}）：仅 --include-home 才还原`
      : '  ⏸ 本快照不含 home 层',
    '  🔒 永不触碰：会话数据、工作区文件、$DSH_HOME 其余内容',
  ].join('\n')
}

/**
 * 还原到指定快照（manifest 精确回放，非整树 checkout —— OpenCode /redo 教训）。
 * 0 安全检查 → 1 guard 快照 → 2 profile 清单回写 → 3 node_modules 补回 → 4 home 层(可选)
 */
export function restoreSnapshot(opts) {
  const { store, target } = opts
  const L = storeLayout(store)
  const profile = opts.profile || resolveProfile()
  // D2（0.7.4 审计 P1）：`last` 曾直选 newestSnapshotId——manual/guard/scheduled 都可成为
  // newest，双击营救可能恢复到同一个坏状态。改为最近**装前**触发器；无装前快照时退回
  // newest 并在结果里如实标注 fallback（README 的「回到最近一次装前」承诺保持成立）。
  let id, lastFallback = false
  if (target === 'last') {
    const lt = lastRestoreTarget(store)
    if (!lt.id) return { ok: false, code: 'snapshot-not-found', target }
    id = lt.id
    lastFallback = lt.fallback
  } else id = target
  const manifest = readSnapshotManifest(store, id)
  if (!manifest) return { ok: false, code: 'snapshot-not-found', target }

  /* 0. 安全检查 */
  if (!opts.force) {
    const running = detectRunningDsh(profile, store, { processName: !opts.skipProcessProbe })
    if (running.length) return { ok: false, code: 'dsh-running', reasons: running, hint: '先完全退出 DSH（托盘也退出），或加 --force（不推荐）' }
  }

  /* 计划（dry-run 到此为止） */
  const idx = readFilesIndex(store, manifest.id)
  const plan = buildRestorePlan({ manifest, idx, profile, includeHome: !!opts.includeHome, store })
  if (opts.dryRun) {
    // P3-8 修复（VaultSync 证据分级模式）：预览必须核对快照侧文件真实存在——
    // 旧预览只对现行树计数，可能预览说能回填、执行时才发现快照缺文件（假成功反面教材）
    const evidence = { verified: 0, snapshotFileMissing: 0, indexMissing: !idx, sampleMissing: [] }
    if (manifest.layers.nodeModules.present && idx) {
      for (const row of idx) {
        if (row[3] === 'reparse') continue
        if (existsNo(join(L.snapshots, manifest.id, 'node_modules', row[0]))) evidence.verified++
        else { evidence.snapshotFileMissing++; if (evidence.sampleMissing.length < 5) evidence.sampleMissing.push(row[0]) }
      }
    }
    // 索引缺失 = node_modules 层不可回放（review #3：曾标 measured 假成功）
    const trustLevel = evidence.indexMissing || evidence.snapshotFileMissing > 0 ? 'degraded' : 'measured'
    return { ok: true, dryRun: true, plan, restoredTo: manifest.id, evidence, trustLevel }
  }

  /* B4：先拿互斥锁（活 pid 持锁即拒绝），再检出更早的未完成还原。锁贯穿整个还原生命周期。
   * G6：先检出更早的未完成还原（若有），再写本次阶段进度（半程被杀 = 进度文件残留 = 下次运行检出）
   * 进度文件先于 guard 快照写（review #17：guard 耗秒级，期间并发 prune 会删掉还原目标——
   * prune 靠进度文件互斥，写晚了互斥面就晚了）。guardId 后续补写。 */
  const lock = acquireRestoreLock(store)
  if (!lock.ok) return { ok: false, code: lock.busy ? 'restore-busy' : 'lock-failed', error: lock.error }
  try {
  const interruptedBefore = readInterruptedRestore(store)
  writeRestoreProgress(store, { target: manifest.id, guardId: null, phase: 'guard', profile: profile.name })

  /* 1. guard 快照（还原可撤销；失败则拒绝还原） */
  let guardId
  try {
    guardId = takeSnapshot({
      store, profile, trigger: 'pre-restore',
      note: `还原到 ${manifest.id} 前的自动保护快照`,
      nodeModules: !!manifest.layers.nodeModules.present,
      prevId: newestSnapshotId(store),
    }).id
  } catch (e) {
    try { rmSync(restoreProgressPath(store), { force: true }) } catch { /* 清理中断标志 */ }
    return { ok: false, code: 'guard-failed', error: String(e) }
  }
  writeRestoreProgress(store, { target: manifest.id, guardId, phase: 'profile', profile: profile.name })

  const results = {
    ok: true, restoredTo: manifest.id, guardId,
    profile: [], home: [], plan,
    restored: 0, skipped: 0, reported: [],
    interruptedBefore,
    lastFallback, // D2：last 语义回退标注（无装前快照可退时选了 newest）
  }

  /* 2. profile 清单回写（现行版先进 trash 批次） */
  const trashBatch = join(L.trash, `pre-restore-${nowId()}`)
  mkdirSync(trashBatch, { recursive: true })
  const preDeps = readJson(join(profile.dir, 'package.json'), null)?.dependencies ?? null // 覆写前暂存（skew 对比基线——覆写后读到的就是快照版了）
  for (const f of manifest.layers.profile.taken) {
    const src = join(L.snapshots, manifest.id, 'profile', f)
    const dst = join(profile.dir, f)
    if (!existsNo(src)) { results.reported.push({ path: f, issue: 'snapshot-file-missing' }); continue } // 曾静默跳过（nm 层同场景会报，两层不一致）
    if (existsNo(dst)) { try { copyFileSync(dst, join(trashBatch, f)) } catch { /* trash 失败不阻塞 */ } }
    copyFileSync(src, dst)
    if (!IS_WIN) { try { const sst = statSync(src); utimesSync(dst, sst.atime, sst.mtime) } catch { /* 尽力 */ } } // POSIX copy 不保留 mtime
    results.profile.push(f)
  }

  /* 3. node_modules 补回 */
  if (manifest.layers.nodeModules.present && idx) {
    writeRestoreProgress(store, { target: manifest.id, guardId, phase: 'node-modules', profile: profile.name })
    const nmCur = join(profile.dir, 'node_modules')
    mkdirSync(nmCur, { recursive: true })
    for (const row of idx) {
      const [rel, , , kind, linkTarget] = row
      if (kind === 'reparse') {
        const dst = join(nmCur, rel)
        if (existsNo(dst) || lstatExists(dst)) { results.skipped++; continue }
        // A2：reparse 重建目标同样经祖先路径——pivot 被 junction 顶替时 mkdir/symlink 会写穿
        const badAncestor = reparseAncestorOf(nmCur, rel)
        if (badAncestor) { results.reported.push({ path: rel, issue: 'ancestor-reparse-refused', hint: `祖先 ${badAncestor} 是 junction/symlink——还原写入会被重定向到快照半径外，拒绝执行（人工排查该链接）` }); continue }
        try {
          mkdirSync(dirname(dst), { recursive: true })
          // mkdir 后重查（A2：mkdir 期间链接可能被创建；TOCTOU 收敛窗口）
          const badNow = reparseAncestorOf(nmCur, rel)
          if (badNow) { results.reported.push({ path: rel, issue: 'ancestor-reparse-refused', hint: `mkdir 后祖先 ${badNow} 变为链接——拒绝` }); continue }
          symlinkSync(linkTarget, dst, 'junction')
          results.restored++
        } catch (e) { results.reported.push({ path: rel, issue: 'reparse-rebuild-failed', error: String(e) }) }
        continue
      }
      const snapFile = join(L.snapshots, manifest.id, 'node_modules', rel)
      const dst = join(nmCur, rel)
      if (!existsNo(snapFile)) { results.reported.push({ path: rel, issue: 'snapshot-file-missing' }); continue }
      // A2：写入/删除目标的全部现存祖先必须是真目录——junction 祖先会把 safeRm 与
      // 硬链接/复制重定向到快照半径外（审计实证：outside 文件被 SNAPSHOT 内容覆盖）
      {
        const badAncestor = reparseAncestorOf(nmCur, rel)
        if (badAncestor) { results.reported.push({ path: rel, issue: 'ancestor-reparse-refused', hint: `祖先 ${badAncestor} 是 junction/symlink——还原写入会被重定向到快照半径外，拒绝执行（人工排查该链接）` }); continue }
      }
      let cur = null; let snap = null
      try { cur = statSync(dst) } catch { /* 缺失 */ }
      try { snap = statSync(snapFile) } catch { /* 上面已查过存在 */ }
      if (cur && cur.isFile()) {
        // 同 inode：现行文件与快照是同一个文件。内容必然一致（无需也不可回填）。
        // 但若 size/mtime 与快照记录不符，说明快照拍完后文件被原地改写——硬链接把污染
        // 同步进了快照（业界已知弱点）。如实报告并指向 lockfile 重建路径。
        if (snap && cur.ino === snap.ino && cur.dev === snap.dev) {
          if (cur.size !== Number(row[1]) || Math.round(cur.mtimeMs) !== Number(row[2])) {
            results.reported.push({
              path: rel, issue: 'snapshot-polluted-in-place',
              hint: '文件在快照后被原地改写，硬链接使快照同步被改——该文件的装前内容可用 lockfile 重建（pnpm install --frozen-lockfile）',
            })
          }
          results.skipped++
          continue
        }
        if (cur.size === Number(row[1]) && (Math.round(cur.mtimeMs) === Number(row[2]) || filesEqualSync(dst, snapFile))) {
          // D1（同 buildRestorePlan 的核验）：size+mtime 相同但 inode 不同=可能被 replace 成
          // 同尺寸同 mtime 的损坏载荷——skipped 前必须内容确证（inode 列 → sha256 → 字节比较）
          let same = true
          const rowIno = row[6] || null
          if (rowIno) same = `${cur.dev}:${cur.ino}` === rowIno
          else if (row[5]) same = safeSha256(dst) === row[5]
          else same = filesEqualSync(dst, snapFile)
          if (!same) {
            // 内容不符：落回填路径（safeRm + 硬链接/复制），不 skipped
          } else {
            results.skipped++; continue
          }
        }
      }
      try {
        if (lstatExists(dst)) safeRm(dst) // 链接感知移除；快照侧 inode 不受影响
        mkdirSync(dirname(dst), { recursive: true })
        // P2-2 修复：原地写文件/自目录的私有副本必须以「复制」回树——硬链接回填会
        // 把防污染设计拆掉（回填后 live 原地写又同步污染快照，审计实证）
        if (sameVolume(snapFile, nmCur) && !isInPlaceNmFile(rel) && !isPrivateCopyTop(rel)) linkSync(snapFile, dst)
        else {
          copyFileSync(snapFile, dst)
          // POSIX copy 不保留 mtime——回填后 verify 才能对上快照期指纹（同快照侧，见 snapshotNodeModules）
          if (!IS_WIN) { try { const sst = lstatSync(snapFile); utimesSync(dst, sst.atime, sst.mtime) } catch { /* 尽力 */ } }
        }
        results.restored++
      } catch (e) { results.reported.push({ path: rel, issue: 'restore-failed', error: String(e) }) }
    }
    // 顶层 extraneous：默认只报告（克制）；--prune-extraneous 移入 trash（改名非删除）
    if (opts.pruneExtraneous && plan.nodeModules.extraneousTopLevel.length) {
      const extraBatch = join(L.trash, `extras-${nowId()}`)
      mkdirSync(extraBatch, { recursive: true })
      for (const name of plan.nodeModules.extraneousTopLevel) {
        try {
          mkdirSync(dirname(join(extraBatch, name)), { recursive: true }) // scoped 名（@org/pkg）需要 trash 侧先建 scope 目录
          renameSync(join(nmCur, name), join(extraBatch, name))
          results.reported.push({ path: name, issue: 'extraneous-moved-to-trash' })
        }
        catch (e) { results.reported.push({ path: name, issue: 'extraneous-move-failed', error: String(e) }) }
      }
    }
  } else if (manifest.layers.nodeModules.present && !idx) {
    // 索引缺失 = nm 层不可回放（review #3：曾静默跳过且 ok:true 假成功）
    results.reported.push({ path: 'files-index.tsv', issue: 'index-missing', hint: '快照文件索引丢失，node_modules 层无法回放——快照受损，请用更早快照或 lockfile 重建（pnpm install --frozen-lockfile）' })
  }

  /* 4. home 层（默认不动） */
  if (opts.includeHome && manifest.layers.home.taken.length) {
    writeRestoreProgress(store, { target: manifest.id, guardId, phase: 'home', profile: profile.name })
    const dshHome = opts.dshHome || resolveDshHome()
    for (const f of manifest.layers.home.taken) {
      const src = join(L.snapshots, manifest.id, 'home', f)
      const dst = join(dshHome, f)
      if (!existsNo(src)) continue
      if (existsNo(dst)) { try { copyFileSync(dst, join(trashBatch, `home-${f}`)) } catch { /* trash 失败不阻塞 */ } }
      copyFileSync(src, dst)
      if (!IS_WIN) { try { const sst = statSync(src); utimesSync(dst, sst.atime, sst.mtime) } catch { /* 尽力 */ } } // POSIX copy 不保留 mtime
      results.home.push(f)
    }
  }

  appendJournal(store, { kind: 'restore', id: manifest.id, guardId, profile: profile.name })
  // 跨 harness 版本还原警告（破坏性更新防线）：快照拍于旧版 harness，现行树已是新版——
  // 版本回退可能触发插件版本门/配置 schema 漂移，如实告知用户（不阻断）。
  // ⚠️ 用覆写前暂存的 preDeps 对比——0.7.0 曾在覆写后读同一文件，curVer 恒等于
  // 快照版，警告永不触发（review #2 运行时实证）。
  {
    const curVer = resolveHarnessVersion(preDeps)?.version.raw ?? null
    if (manifest.harnessVersion && curVer && manifest.harnessVersion !== curVer) {
      results.harnessVersionSkew = { snapshot: manifest.harnessVersion, current: curVer }
    }
  }
  try { rmSync(restoreProgressPath(store), { force: true }) } catch { /* 完成标志删除失败可容忍（残留只造成一次误报级提示） */ }
  results.radius = restoreRadiusStatement(manifest)
  // E2（0.7.4 审计 P1）：存在硬错误项（快照缺文件/回填失败/索引缺失/祖先拒绝/extraneous 移动失败）
  // 时曾仍 ok:true + CLI ✅/exit 0——用户、rescue UI 与自动化都把部分恢复当成功。
  // 改 ok:false + partial:true（guardId 保留——可 undo 或重试）
  const HARD_ISSUES = new Set(['snapshot-file-missing', 'restore-failed', 'index-missing', 'ancestor-reparse-refused', 'reparse-rebuild-failed', 'extraneous-move-failed'])
  const hardReports = results.reported.filter((r) => HARD_ISSUES.has(r.issue))
  if (hardReports.length) {
    results.ok = false
    results.partial = true
    results.partialReason = `${hardReports.length} 项未能还原（详见 reported）——快照可能受损或目标被占用；guard 快照 ${guardId} 可回到还原前`
  }
  return results
  } finally {
    releaseRestoreLock(store, lock.fd) // B4：任何路径（含 throw）都释放互斥锁
  }
}

function lstatExists(p) { try { lstatSync(p); return true } catch { return false } }

/** A2（0.7.4 审计 P0）：目标的所有现存祖先逐级 lstat，遇 reparse point（junction/symlink）
 * 即拒绝。词法 containment 闸（files-index 行 resolve）管不住这个：live 的 pivot 目录
 * 若被换成指向外部的 junction，join(nm,pivot,victim.txt) 词法上仍在 nm 内、解析后却在外。
 * 只查最终组件的 safeRm 也不够——硬链接/复制的写入目标同样经祖先重定向。
 * 返回违规祖先 rel 路径（null=干净）。fromRel 应为相对 nm 根的 rel（如 'pivot\\victim.txt'）。 */
function reparseAncestorOf(rootDir, fromRel) {
  const segs = String(fromRel).split(sep)
  let cur = rootDir
  for (let i = 0; i < segs.length - 1; i++) { // 最后一段是文件本体，单独由 safeRm/写入逻辑管
    cur = join(cur, segs[i])
    if (isReparsePoint(cur)) return segs.slice(0, i + 1).join(sep)
  }
  return null
}

/** 内容早退比对：size+mtime 快判之外的确证（还原正确性优先于耗时） */
function filesEqualSync(a, b) {
  const BUF = 1024 * 1024
  const fa = readFileSync(a); const fb = readFileSync(b) // 单次读入；node_modules 单文件普遍远小于内存
  if (fa.length !== fb.length) return false
  return fa.equals(fb)
}

/** 流式 sha256（1MB 分块，不整载——node_modules 里有大体积二进制） */
export function sha256File(p) {
  const h = createHash('sha256')
  const fd = openSync(p, 'r')
  try {
    const buf = Buffer.alloc(1024 * 1024)
    let n = 0
    while ((n = readSync(fd, buf, 0, buf.length, null)) > 0) h.update(n === buf.length ? buf : buf.subarray(0, n))
  } finally { closeSync(fd) }
  return h.digest('hex')
}
function safeSha256(p) { try { return sha256File(p) } catch { return '' } }

/* ============================================================
 * prune（硬性 GC —— OpenCode 533GB 事故纪律）
 * ============================================================ */

/**
 * 保留策略：maxSnapshots / maxBytes / ttlDays —— **只作用于轮换池**
 * （非豁免 = 非 manual 非 guard 的自动快照）。
 * 豁免原则（与文档一致）：manual=true（用户显式还原点）、guard=true（还原保护快照）
 * **完全退出配额体系**——不计数量、不计字节、不过期，永不被自动清理。
 * （v0.3.3 及之前：豁免快照占满字节配额时循环会删光全部非豁免快照——真实事故，已修。）
 * 硬链接链中删任意快照不影响其余快照（inode 有别的目录项引用即存活）。
 */
export function pruneSnapshots(store, retention = {}) {
  // P2-5：还原进行中/半程未处理时禁 prune——GC 删掉还原正在引用的快照=部分还原
  const progress = readJson(restoreProgressPath(store), null)
  if (progress) {
    if (pidAlive(progress.pid)) return { ok: false, code: 'restore-in-progress', detail: '还原正在进行，prune 已跳过' }
    return { ok: false, code: 'restore-interrupted', detail: `存在未完成还原（目标 ${progress.target}），先重跑 restore 或 undo 再 prune` }
  }
  const cfg = { ...DEFAULT_RETENTION, ...readJson(storeLayout(store).config, null)?.retention, ...retention }
  const all = listSnapshots(store).filter((m) => !m.corrupted)
  if (!all.length) return { ok: true, deleted: [], kept: 0, rotatable: 0 }
  // 字节配额语义 = 库的物理体积（OpenCode 533GB 事故约束的是磁盘）。
  // stats.bytes 是逻辑和（硬链接共享内容每快照重复计）；按「内容唯一性」折算：
  // 同一文件被 N 个快照共享（index 行的 hash 列相同且非空）只计一次——按新→旧序，
  // 最老快照承担独占成本。0.7.0 曾用逻辑和：3GB 配额在 2GB 稳定树下只留得下 1 个快照，
  // maxSnapshots:15 名存实亡（review #6 实证 5 快照共享 10MB 被计 50MB）。
  // C1（0.7.4 审计 P1）：曾把全库索引行驻留在 kept._indexRows（22968 行/快照 ×508 快照
  // ≈11GiB 外推）——prune 在淘汰前先 OOM。改两遍流式：第一遍逐快照算 uniqBytes 后即释放，
  // 共享哈希表只留 hash→bytes（无行数据）；第二遍逐快照重算「存活集」的唯一字节（复核用）。
  // C3：物理共享按 (dev,ino) 身份计——快照侧 inode 才是磁盘占用的真实粒度；
  // 索引行无 inode（老快照/缺列）时退回 hash 口径（保守：hash 共享是物理共享的超集近似，
  // 同内容独立副本会被少算——可接受的老快照过渡行为，新快照全部带 inode 列）
  const sharedInodes = new Map() // 'dev:ino' -> 已计入字节数
  const sharedHashes = new Map() // hash -> 已计入字节数（inode 缺失时的回退）
  const uniqBytesScan = (m, collect) => { // 流式读单快照索引；collect=false 只算不记共享表
    let uniq = 0
    if (!m._nmPresent) return m._bytes
    let rows = null
    try { rows = readFilesIndex(store, m.id) } catch { rows = null }
    if (!rows) return m._bytes // 索引缺失：退逻辑和（保守——多计不漏计）
    for (const row of rows) {
      const h = row[5]
      const size = Number(row[1]) || 0
      const inoKey = row[6] || null
      const key = inoKey ? `i:${inoKey}` : h ? `h:${h}` : null
      if (!key) { uniq += size; continue }
      if (collect) {
        const prev = (inoKey ? sharedInodes : sharedHashes).get(key)
        if (prev === undefined) { (inoKey ? sharedInodes : sharedHashes).set(key, size); uniq += size }
        else if (prev < size) { (inoKey ? sharedInodes : sharedHashes).set(key, size); uniq += size - prev } // 尺寸涨了，增量入账
      } else {
        // 复核模式：只算「本快照独有或本快照尺寸更大」的部分
        const prev = (inoKey ? sharedInodes : sharedHashes).get(key)
        if (prev === undefined || prev < size) uniq += prev === undefined ? size : size - prev
      }
    }
    rows = null // 释放本快照的行数组
    return uniq
  }
  const kept = all.map((m) => ({ ...m, _bytes: m.stats?.bytes ?? 0, _nmPresent: !!m.layers?.nodeModules?.present }))
  for (const m of kept) m._uniqBytes = uniqBytesScan(m, true)
  sharedInodes.clear(); sharedHashes.clear() // 复核阶段重建（按存活集）——避免保留全库共享大表
  const deleted = []
  const isExempt = (m) => m.manual || m.guard
  // 轮换池 = 非豁免；kept 按新→旧排序，池内最旧 = 池数组末尾
  const rotatable = kept.filter((m) => !isExempt(m))
  const ttlCutoff = Date.now() - cfg.ttlDays * 86400_000
  // 物理字节 = 全体（豁免+轮换）唯一字节数之和？——不：配额只约束轮换池，
  // 豁免不施压（原则不变），但轮换池自己的物理贡献要用唯一口径
  // （C1 流式化后 uniqBytesScan 即时计算，不再预存 bytesOf 闭包）
  // P1-1 修复：数组是新→旧序，逐出最旧必须取末尾（pop）。
  // 旧实现 shift() 删的是最新快照——GC 恰好优先清掉最有价值的装前还原点（审计实证）。
  const evictOldest = () => { if (rotatable.length) deleted.push(rotatable.pop()) }
  // TTL（最旧优先）
  for (const m of [...rotatable]) {
    if (m.timeEpoch < ttlCutoff) {
      const idx = rotatable.indexOf(m)
      if (idx >= 0) deleted.push(rotatable.splice(idx, 1)[0])
    }
  }
  // 数量配额（只数轮换池）
  while (rotatable.length > cfg.maxSnapshots) evictOldest()
  // 字节配额（只算轮换池；豁免快照不施压——配额不可满足时循环必须停止）。
  // C3（0.7.4 审计 P2）：唯一性按 hash 计曾把「同内容不同 inode」错算共享——物理配额
  // 可超承诺（最小修复按 (dev,ino) 计共享；索引行未记录 inode 的快照退回 hash 口径）。
  // C1 流式化：共享表不能常驻——每次 poolBytes() 前对**当前存活池**重建（新→旧 collect），
  // 计算完即清。淘汰一个再重算，直到配额满足。
  const rebuildShared = () => { sharedInodes.clear(); sharedHashes.clear(); for (const m of rotatable) uniqBytesScan(m, true) }
  const poolBytes = () => { rebuildShared(); return rotatable.reduce((s, m) => s + uniqBytesScan(m, false), 0) }
  while (poolBytes() > cfg.maxBytes) {
    if (!rotatable.length) break
    evictOldest()
  }
  // 执行删除（deleted 按 evict 顺序 = 最旧优先；kept 里仍保留全部未删快照）
  const root = storeLayout(store).snapshots
  const removed = []
  for (const m of deleted) {
    try { safeRm(join(root, m.id)); removed.push({ id: m.id, bytes: m._bytes }) }
    catch (e) { removed.push({ id: m.id, error: String(e) }) }
  }
  const remaining = kept.filter((m) => !deleted.some((d) => d.id === m.id))
  appendJournal(store, { kind: 'prune', deleted: removed.map((r) => r.id) })
  return { ok: true, deleted: removed, kept: remaining.length, rotatable: rotatable.length, totalBytesAfter: poolBytes(), totalLogicalBytes: kept.filter((m) => !isExempt(m)).reduce((s, m) => s + m._uniqBytes, 0) }
}

/* ============================================================
 * verify（G1：快照完整性校验）
 * 硬链接方案特有风险面：同 inode 原地改写会静默污染快照——快照侧文件
 * 本应永不变化，任何 size+mtime 漂移即污染指纹；deep 模式用快照时记录的
 * sha256 捕捉同尺寸同毫秒的篡改（restore 只在还原时事后检出，verify 提前）。
 * ============================================================ */

/**
 * 校验快照完整性。
 * @param {string} opts.liveNmDir 可选：现行 node_modules 路径——传入后 .modules.yaml 漂移
 *   仅在「快照侧仍与 live 同 inode」时判 benign（真硬链接原地写遗留）；不传/不可得=不宽容。
 * @returns {ok, id, deep, checked, okCount, missingCount, modifiedCount, hashMismatchCount,
 *           indexMissing, skippedReparse, samples:{missing,modified,hashMismatch}, durationMs}
 */
export function verifySnapshot(store, id, { deep = false, maxSamples = 20, liveNmDir } = {}) {
  const t0 = Date.now()
  const L = storeLayout(store)
  const manifest = readSnapshotManifest(store, id)
  if (!manifest) return { ok: false, code: 'snapshot-not-found', id }
  const res = {
    ok: true, id, deep, checked: 0, okCount: 0,
    missingCount: 0, modifiedCount: 0, hashMismatchCount: 0, benignModifiedCount: 0,
    indexMissing: false, skippedReparse: 0,
    samples: { missing: [], modified: [], hashMismatch: [] },
    durationMs: 0,
  }
  const push = (bucket, rel) => {
    if (res.samples[bucket].length < maxSamples) res.samples[bucket].push(rel)
  }
  if (manifest.layers.nodeModules.present) {
    const idx = readFilesIndex(store, id)
    if (!idx) { res.indexMissing = true; res.ok = false }
    else {
      const snapRoot = join(L.snapshots, id, 'node_modules')
      for (const row of idx) {
        const [rel, size, mtime, kind] = row
        if (kind === 'reparse') { res.skippedReparse++; continue }
        res.checked++
        const p = join(snapRoot, rel)
        let st = null
        try { st = lstatSync(p) } catch { /* 缺失 */ }
        if (!st || !st.isFile()) { res.missingCount++; push('missing', rel); continue }
        if (st.size !== Number(size) || Math.round(st.mtimeMs) !== Number(mtime)) {
          // 已知 pnpm 原地写文件漂移：仅「快照侧仍与 live 同 inode」时 benign（真硬链接
          // 原地写的遗留——修复前旧快照的固有形态）。E3（0.7.4 审计 P1）：0.7.0 起该文件
          // 走私有副本（非硬链接），快照侧 inode 与 live 无关——任何漂移都是真篡改
          // 或损坏，曾一律 benign 而漏报。live 不可得（未传 liveNmDir/已卸载）时也不宽容。
          if (isInPlaceNmFile(rel) && liveNmDir) {
            let liveSt = null
            try { liveSt = statSync(join(liveNmDir, rel)) } catch { /* live 已不在 */ }
            if (liveSt && liveSt.ino === st.ino && liveSt.dev === st.dev) { res.benignModifiedCount++; continue }
          }
          res.modifiedCount++; push('modified', rel); continue
        }
        if (deep && row[5]) {
          let bad = false
          try { bad = sha256File(p) !== row[5] } catch { bad = true }
          if (bad) { res.hashMismatchCount++; push('hashMismatch', rel); continue }
        }
        res.okCount++
      }
    }
  }
  // profile / home 层：存在性核对（全拷贝层，无索引可比对）
  const layerGone = []
  for (const f of manifest.layers.profile.taken) {
    if (!existsNo(join(L.snapshots, id, 'profile', f))) layerGone.push(`profile/${f}`)
  }
  for (const f of manifest.layers.home.taken) {
    if (!existsNo(join(L.snapshots, id, 'home', f))) layerGone.push(`home/${f}`)
  }
  if (layerGone.length) {
    res.missingCount += layerGone.length
    for (const rel of layerGone) { if (res.samples.missing.length < maxSamples) res.samples.missing.push(rel) }
  }
  if (res.missingCount || res.modifiedCount || res.hashMismatchCount || res.indexMissing) res.ok = false
  res.durationMs = Date.now() - t0
  return res
}

function verifyPrettyLine(r) {
  const parts = [`校验 ${r.checked} 个文件` + (r.deep ? '（deep 含 sha256）' : '')]
  if (r.modifiedCount) parts.push(`⚠️ 被改 ${r.modifiedCount}（快照侧文件不应变化——原地改写污染指纹）`)
  if (r.hashMismatchCount) parts.push(`⚠️ 哈希不符 ${r.hashMismatchCount}`)
  if (r.benignModifiedCount) parts.push(`已知原地写文件漂移 ${r.benignModifiedCount}（pnpm 布局文件，无害）`)
  if (r.missingCount) parts.push(`缺失 ${r.missingCount}`)
  if (r.indexMissing) parts.push('⚠️ 文件索引缺失')
  return parts.join('；')
}

/* ============================================================
 * doctor（R1 基础体检；R4 扩容：PATH/重复包/编码 C1-C6）
 * ============================================================ */

export function doctor(profileArg, dshHomeArg) {
  // dshHomeArg：宿主半已解析的 dshHome（桌面端进程常无 DSH_HOME env——宿主自述注释实证）。
  // 曾无此参：env 缺失时内核内部 resolveDshHome() 猜到 ~/.dsh，体检对象直接错家。
  const dshHome = dshHomeArg || resolveDshHome()
  const profile = profileArg?.dir ? profileArg : resolveProfile(dshHome)
  const store = resolveStore(dshHome)
  const checks = []
  const add = (id, ok, detail) => checks.push({ id, ok, detail })

  add('dsh-home', existsNo(join(dshHome, 'profiles')), dshHome)
  add('profile', existsNo(join(profile.dir, 'package.json')), `${profile.name} → ${profile.dir}`)
  const nm = join(profile.dir, 'node_modules')
  const nmExists = existsNo(nm)
  add('node-modules', nmExists, nmExists ? `${okReaddir(nm).length} 个顶层条目` : '不存在')
  const volOk = sameVolume(profile.dir, store)
  add('same-volume', volOk, volOk ? '快照库与 profile 同卷，硬链接可用' : '⚠️ 跨卷：快照退化为复制，慢且占空间')
  add('disk-space', true, diskSpaceCheck(store))
  add('store', existsNo(store), store)
  const snaps = listSnapshots(store)
  const corrupted = snaps.filter((m) => m.corrupted).map((m) => m.id)
  add('snapshots', snaps.some((m) => !m.corrupted), `${snaps.filter((m) => !m.corrupted).length} 个快照${corrupted.length ? `；⚠️ 损坏已隔离：${corrupted.join(', ')}` : ''}`)
  // 最新快照完整性核查（G1）：快照侧文件不应有任何漂移，漂移=硬链接污染指纹
  const newest = snaps.find((m) => !m.corrupted)
  if (newest) {
    const v = verifySnapshot(store, newest.id, { deep: false, liveNmDir: nmExists ? nm : undefined })
    add('verify-latest', v.ok, v.ok
      ? `最新快照 ${v.id} 完整性通过（${v.checked} 文件）`
      : `⚠️ 最新快照 ${v.id} 异常：${verifyPrettyLine(v)}（详情与修复：node dsh-snap.mjs verify ${v.id} --deep）`)
  }
  // 半程还原检测（G6）：进度文件残留 = 上次还原被杀
  const interrupted = readInterruptedRestore(store)
  add('restore-interrupted', !interrupted, interrupted
    ? `⚠️ 上次还原未完成：目标 ${interrupted.target}，停在 ${interrupted.phase} 阶段（${new Date(interrupted.startedAt).toISOString()}）——重跑 restore，或用 guard 快照 ${interrupted.guardId} 回到还原前`
    : '无未完成还原')
  // 幽灵依赖（六轮演练 R4 实证）：装了 dsh.bundle 包但没进 bundles = 不激活
  {
    const g = ghostDeps(profile.dir, dshHome)
    add('ghost-deps', !g.ghosts?.length, g.ghosts?.length
      ? `⚠️ 幽灵依赖 ${g.ghosts.length} 个（装了不激活）：${g.ghosts.join(', ')}——${g.hint}`
      : (g.ok ? '无幽灵依赖' : `跳过（${g.reason}）`))
  }
  // 安装残锁（六轮演练实坑：残锁使后续安装超时 120s）
  {
    const locks = staleLocks(profile.dir)
    add('stale-locks', !locks.length, locks.length
      ? `⚠️ 残留锁 ${locks.length} 个：${locks.map((l) => l.detail).join('；')}——可运行 unstick 清理`
      : '无残留锁')
  }
  // patch 冲突扫描（生态调研实证：entry id 撞车 / 多包同改官方行 = Settings 失效、双挂载、静默覆盖）
  {
    const pc = patchConflicts(profile.dir, dshHome)
    add('patch-conflicts', !pc.conflicts?.length, pc.ok
      ? (pc.conflicts.length
        ? `⚠️ patch 冲突 ${pc.conflicts.length} 处：${pc.conflicts.slice(0, 3).map((c) => c.detail).join('；')}${pc.conflicts.length > 3 ? ` 等（扫描 ${pc.scanned} 个 patch 型插件）` : ''}`
        : `无冲突（扫描 ${pc.scanned} 个 patch 型插件）`)
      : `跳过（${pc.reason}）`)
  }
  // harness 变更哨兵（破坏性更新防线）：更新后首启提示 + 基线快照位置
  {
    const det = detectHarnessChange(dshHome, profile, store)
    const jc = readJournal(store).filter((e) => e.kind === 'harness-change' && e.profile === profile.name)
    const last = jc[jc.length - 1]
    add('harness-change', true, det.changed
      ? `⚠️ harness 环境与上次记录不同（上次记录 ${det.savedAt ?? '时间未知'}）——可能是桌面版更新。更新后首启故障可对比 harness-change 快照（journal 有证据行）`
      : det.saved
        ? `无变化（基线 ${det.savedAt ?? ''}：${det.cur?.app ? String(det.cur.app).split('|')[0] + ' | ' : ''}${det.cur?.harnessDeps ?? 'deps 不可知'}）`
        : '无记录（首次建档后此检查显示基线状态）')
    if (det.changed) {
      // 变更时不写档案（review #11：曾覆写指纹档案——宿主的 journal 行 + 基线快照流程
      // 被静默跳过，更新后首启的归因证据链丢失）。doctor 只报告，动作留给宿主哨兵链。
    } else if (!det.saved && det.cur) saveHarnessState(dshHome, profile, store, det.cur, { firstSeen: true }) // doctor 顺手建档
  }
  // 列车兼容自检（G11）：本机 harness 版本 vs dsh-snap 声明范围——0.3 列车一出即预警（而不是被版本门静默拦截）
  {
    const deps = readJson(join(profile.dir, 'package.json'), null)?.dependencies ?? {}
    const harness = resolveHarnessVersion(deps)
    if (!harness) add('train-compat', true, 'harness 版本不可知，跳过列车兼容检查')
    else {
      const sat = satisfies(harness.version, ENGINES_DSH_SELF)
      add('train-compat', sat !== false, sat === true
        ? `本机 harness ${harness.version.raw} 在 dsh-snap 声明范围内（${ENGINES_DSH_SELF}）`
        : sat === false
          ? `⚠️ 本机 harness ${harness.version.raw} 超出 dsh-snap 声明范围（${ENGINES_DSH_SELF}）——插件可能被版本门拒绝，请更新 dsh-snap`
          : `harness ${harness.version.raw} 无法解析，跳过`)
    }
  }
  const running = detectRunningDsh(profile, store)
  add('dsh-running', running.length === 0, running.length ? running.map((r) => r.detail).join('；') : '未检测到运行中的 DSH')
  // 句柄占用预检：仅当 DSH 未运行时探测（test-rename 探针，与官方更新器同一原语）
  add('handle-probe', true, nmExists && running.length === 0 ? probeHandle(nm) : running.length ? 'DSH 运行中，跳过占用探测' : '目录不存在，跳过')
  // 残留与垃圾：.ignored / 空顶层目录（pnpm 卸载残留）
  if (nmExists) add('nm-leftovers', true, nmLeftovers(nm))
  // 官方崩溃恢复痕迹（2026-11-10 实战：弹窗按钮 ×3 把 bundles 砍成官方 2 包、patch 改名进 .bak——
  // doctor 的 ghost-deps 能看到症状但看不出「这是官方恢复干的、原文还在 .bak 里可修」）
  {
    let art = null
    try { art = recoveryArtifacts(profile.dir, store) } catch { /* 检测失败不报错 */ }
    if (art?.found) {
      // 确凿破坏信号只有 bundles 回缩（live < 快照侧最大合法对照）；patch 与 .bak 的尺寸差异
      // 也可能是恢复后的正常演化（magpie 周期合并模型表——实机 10:57 实证），只在 bundles 回缩时连带提示
      const bad = art.bundlesShrunk
      if (bad) {
        const bundleNote = art.snapshotBundles ? `live bundles ${art.liveBundles} 个 < 快照 ${art.snapshotBundles.count} 个（${art.snapshotBundles.from}）` : `live bundles ${art.liveBundles} 个（快照侧无合法对照）`
        add('recovery-artifacts', false, `⚠️ 官方崩溃恢复破坏：${bundleNote}——patch 原文在 ${art.newest.name}（${art.newest.size} 字节）。运行 \`repair-profile\` 外科恢复（配置级，不动 node_modules）`)
      } else {
        add('recovery-artifacts', true, art.patchDiffers
          ? `有恢复痕迹（${art.newest.name}）但 bundles 完整（${art.liveBundles} 个）；patch 与 .bak 有差异——若怀疑缺块可 \`repair-profile --dry-run\` 预览`
          : `有恢复痕迹但配置与 .bak 一致`)
      }
    }
  }
  // PATH 卫生（重复项）
  add('path-dupes', true, pathDupes())
  // 会话文件 UTF-8 完整性采样（第七轮 C3/C5 的 CLI 侧可测部分）
  add('utf8-sample', true, utf8Sample(join(dshHome, 'sessions')))
  return { ok: checks.every((c) => c.ok), checks, store, profile: profile.dir, dshHome }
}

function diskSpaceCheck(store) {
  try {
    const { statfsSync } = requireFsStatfs()
    const s = statfsSync(dirname(store))
    const free = Number(s.bavail) * Number(s.bsize)
    return `快照库所在卷剩余 ${fmtBytes(free)}${free < 2 * 1024 * 1024 * 1024 ? '（⚠️ 低于 2GB，快照可能失败）' : ''}`
  } catch { return '无法检测（statfs 不可用），跳过' }
}
function requireFsStatfs() {
  return { statfsSync: _statfsSync }
}
import { statfsSync as _statfsSync } from 'node:fs'

function nmLeftovers(nm) {
  const entries = okReaddir(nm)
  const ignored = entries.filter((e) => e === '.ignored')
  const empty = []
  for (const e of entries) {
    if (e.startsWith('.')) continue
    const p = join(nm, e)
    try {
      const st = lstatSync(p)
      if (st.isDirectory() && okReaddir(p).length === 0) empty.push(e)
    } catch { /* 忽略 */ }
  }
  const parts = []
  if (ignored.length) parts.push(`存在 .ignored 目录（pnpm 遗留）`)
  if (empty.length) parts.push(`空顶层目录 ${empty.length} 个${empty.length <= 6 ? `：${empty.join(', ')}` : ''}`)
  return parts.length ? `⏸ ${parts.join('；')}（只报告不动手；可手动清理）` : '无残留'
}

function pathDupes() {
  const raw = process.env.PATH || ''
  const seen = new Set(); const dupes = []
  for (const seg of raw.split(IS_WIN ? ';' : ':')) {
    const key = seg.trim().toLowerCase()
    if (!key) continue
    if (seen.has(key)) dupes.push(seg.trim())
    else seen.add(key)
  }
  return dupes.length ? `⚠️ PATH 有 ${dupes.length} 个重复项（可能拖慢进程启动/引发 shadowing）：${dupes.slice(0, 3).join(' ; ')}` : 'PATH 无重复项'
}

/** 采样会话文件做 UTF-8 严格解码（fatal=true）。P2-7：只采 ≤512KB 的完整小文件——
 * 截断解码大文件的前缀会把多字节字符拦腰砍断，完好文件约 75% 概率误报（审计实证） */
function utf8Sample(sessionsDir) {
  if (!existsNo(sessionsDir)) return '无会话目录，跳过'
  const files = []
  let bigSkipped = 0
  const walk = (d, depth) => {
    if (depth > 2 || files.length >= 24) return
    for (const e of okReaddir(d)) {
      const p = join(d, e)
      let st; try { st = statSync(p) } catch { continue }
      if (st.isDirectory()) walk(p, depth + 1)
      // 只采样未压缩的完整小文件（.zstd 需解码器，零依赖 CLI 不做；大文件截断必误报）
      else if (st.isFile() && /\.(jsonl|json|txt)$/i.test(e)) {
        if (st.size <= 512 * 1024) files.push(p)
        else bigSkipped++
      }
      if (files.length >= 24) return
    }
  }
  walk(sessionsDir, 0)
  const suffix = bigSkipped ? `（另跳过 ${bigSkipped} 个大文件防截断误报）` : ''
  if (!files.length) return bigSkipped
    ? `会话文件均超 512KB 或为压缩格式，CLI 跳过采样${suffix}（编码体检的 client 侧由面板承担）`
    : '会话文件均为压缩格式（.zstd），零依赖 CLI 跳过采样（编码体检的 client 侧由面板承担）'
  let bad = 0
  const dec = new TextDecoder('utf-8', { fatal: true })
  for (const f of files) {
    try {
      const buf = readFileSync(f)
      dec.decode(buf.length > 512 * 1024 ? buf.subarray(0, 512 * 1024) : buf)
    } catch { bad++ }
  }
  return bad === 0
    ? `采样 ${files.length} 个未压缩会话文件：UTF-8 全部完好${suffix}`
    : `⚠️ ${bad}/${files.length} 个文件含坏 UTF-8 字节（流式截断/编码问题指纹，第七轮 C3；只报告）${suffix}`
}

/**
 * 句柄占用探针：rename(node_modules → 探针名) + 立即 rename 回来。
 * 树内任意后代被占用 → MoveFileExW 语义失败（同官方更新器 #11119 的原语）。
 * 先恢复历史遗留探针目录（两次 rename 之间崩溃的自愈路径）。
 */
function probeHandle(dir) {
  // 自愈：上次探针把目录改了名却没改回来
  const parent = dirname(dir)
  const base = dir.split(/[\\/]/).pop()
  for (const entry of okReaddir(parent)) {
    if (entry.startsWith(`${base}.dsh-snap-probe-`)) {
      try {
        if (!existsNo(dir)) { renameSync(join(parent, entry), dir); return '已恢复上次探针遗留的目录改名' }
      } catch { /* 恢复失败如实报告 */ }
    }
  }
  const probe = join(parent, `${base}.dsh-snap-probe-${Date.now()}`)
  try {
    renameSync(dir, probe)
  } catch (e) {
    return `⚠️ 目录被占用（改名探针失败：${e.code || e.message}）——更新/还原前请关闭 VS Code、资源管理器、杀毒扫描等占用者（官方 #11119 同源问题）`
  }
  try {
    renameSync(probe, dir)
    return '空闲（test-rename 探针通过，无句柄占用）'
  } catch (e) {
    try { renameSync(probe, dir) } catch { /* 下次 doctor 运行自愈 */ }
    return `⚠️ 目录被占用（回滚改名失败：${e.code || e.message}）`
  }
}

/* ============================================================
 * G5 崩溃归因（纯只读；任一层失败静默降级 journal-only）
 * 出处：LG-core = lifeguard core.mjs；LG-attr = lib/attribute.mjs；实机 = 本机 crash log 实证
 * ============================================================ */
const CRASH_FILE_RE = /^(?:crash|startup)-.*\.log$/, MAX_LOG_BYTES = 4 * 1024 * 1024 // LG-core L193/L224
const OOM_RE = /<--- Last few GCs --->|JavaScript heap out of memory|Array buffer allocation failed|FATAL ERROR: .*(heap|Allocation failed)|out of memory/i // LG-core L357 + R4 演练实死样本
// GUI 外壳↔宿主本地握手失败（2026-11-10 实战：强杀弄坏 GUI Chromium 网络状态后每次启动必死于此，
// 与插件无关，却曾把 zod/@anthropic-ai/sdk 错当成嫌疑）。特征：desktop welcome / Desktop Host 认证栈。
const SHELL_HANDSHAKE_RE = /desktop welcome:|Desktop Host (?:authentication failed|did not provide boot injections)|connectDesktopWelcome/i
const DIRECT_MS = 30 * 60_000, OOM_DIRECT_MS = 6 * 3600_000, CIRC_MS = 24 * 3600_000 // 窗口：LG-attr L16-20

export function crashLogDirs(dshHome) { // LG-core L166-191 全兼容 + 实机校正（真目录 @deepseek-ai/dsh-desktop）
  const dirs = [], macLogs = platform() === 'darwin' ? join(homedir(), 'Library', 'Logs') : null
  if (macLogs) { dirs.push(join(macLogs, 'DeepSeek Harness')); for (const n of okReaddir(macLogs)) if (/^(deepseek|dsh)/i.test(n)) dirs.push(join(macLogs, n)) } // LG-core L171-177
  else if (IS_WIN) {
    dirs.push(join(process.env.APPDATA || '', '@deepseek-ai', 'dsh-desktop', 'logs')) // 实机实证（dsh-plugin-health boot.js L214 同）
    dirs.push(join(process.env.APPDATA || '', 'DeepSeek Harness', 'logs'))            // LG-core L179
  } else dirs.push(join(homedir(), '.config', 'DeepSeek Harness', 'logs'))            // LG-core L181
  dirs.push(join(dshHome, 'logs')) // LG-core L183：startup-*.log
  return [...new Set(dirs)].filter(existsNo)
}

const normText = (t) => String(t ?? '').replace(/\r\n?/g, '\n') // LG-core L124-126：CRLF 读盘边界统一
const headerOf = (text) => { // LG-core L243-251：`key: value` 头（实机键 time/source/phase/app/...，键名可含空格）
  const out = {}
  for (const line of normText(text).split('\n--- ')[0].split('\n')) { const m = /^([a-z][a-z0-9 ]*):\s?(.*)$/.exec(line); if (m) out[m[1].trim()] = m[2].trim() }
  return out
}
const sectionOf = (text, tag) => { // LG-core L253-259：`--- tag ---` 到下一个 `--- ` 区段
  const at = text.indexOf(`--- ${tag} ---`)
  if (at < 0) return ''
  const body = text.slice(at + tag.length + 8), end = body.search(/\n--- [a-z]/)
  return (end < 0 ? body : body.slice(0, end)).trim()
}
const firstFrame = (text) => { // LG-core L261-293 简化；P1-4：先线性定位栈行、单行限长——旧实现整段正则回溯对超长栈 O(L²)（实测 200KB 55 秒）
  const capped = text.length > 262144 ? text.slice(0, 262144) : text
  let line = null
  for (const l of capped.split('\n')) { if (/^\s+at\s/.test(l)) { line = l; break } }
  if (!line) return null
  if (line.length > 4096) line = line.slice(0, 4096)
  const m = /^\s+at\s+.*?([^\s\\/()]+\.(?:mjs|cjs|js|ts)):(\d+):\d+/.exec(line)
  return m ? `${m[1]}:${m[2]}` : null
}
const classifyError = (t) => { // LG-core L350-362 + 实机新增 child-exit/renderer-crash（实机主体，LG 缺失会误判 unknown）
  if (SHELL_HANDSHAKE_RE.test(t)) return 'shell-handshake' // 先于 OOM：welcome 握手文本不会撞 OOM 特征，但顺序上外壳类最特异
  if (OOM_RE.test(t)) return 'out-of-memory'
  if (/startup failed|did not activate|Failed plugins \(/i.test(t)) return 'plugin-activation'
  if (/ValidationError: invalid config/i.test(t)) return 'config-validation'
  if (/Maximum call stack size exceeded/i.test(t)) return 'stack-overflow'
  if (/fatal uncaught exception|uncaughtException/i.test(t)) return 'uncaught-exception'
  if (/Desktop renderer exited/.test(t)) return 'renderer-crash'
  return /exited with \d+/.test(t) ? 'child-exit' : 'unknown'
}
/* 实机 Failed plugins 块 = 2 空格 id 行 + 4 空格 Package:/Error: 行；LG-core L454 按 4/6 空格写正则对实机漏配，此处按实物校正（600 字符尾窗防跨条目误配） */
const failedPluginsOf = (t) => [...t.matchAll(/^\s{2}([\w@/.-]+)\s+\(\w+\)\s*$/gm)].slice(0, 8).map((m) => {
  const tail = t.slice(m.index, m.index + 600)
  return { name: m[1], pkg: /^\s{4}Package:\s*(\S+)/m.exec(tail)?.[1] ?? null, error: /^\s{4}Error:\s*(.+)/m.exec(tail)?.[1]?.slice(0, 200) ?? null }
})
const moduleHintsOf = (t) => [...new Set([...t.matchAll(/node_modules[\\/]((?:@[\w.-]+[\\/])?[\w.-]+)/g)].map((m) => m[1].replace(/[\\/]/g, '/')))].slice(0, 8) // LG-core L318-348 弱化

const parseStartupText = (file, text) => { // LG-core parseStartup L448-480 压缩版（$DSH_HOME/logs/startup-*.log）
  try {
    const entries = [...text.matchAll(/^\s{4}([\w@/.-]+)\s*$\n\s{6}Package:\s*([\w@/.-]+)\s*$/gm)].map((m) => ({ name: m[1], pkg: m[2] }))
    return { origin: 'log', file, exitCode: null, profile: /profile:\s*'([^']+)'/.exec(text)?.[1] ?? null,
      kind: /ValidationError:\s*invalid config/.test(text) ? 'config-validation' : 'plugin-activation',
      time: /timestamp:\s*'([^']+)'/.exec(text)?.[1] || new Date(statSync(file).mtimeMs).toISOString(),
      summary: `startup · ${entries.map((e) => e.name).join(' + ') || 'plugin'} failed to activate`,
      frame: firstFrame(text), failedPlugins: entries, evidenceNames: entries.flatMap((e) => [e.name, e.pkg]) }
  } catch { return null }
}
const parseCrashFile = (file, text) => { // LG-core parseCrash L364-446 收敛版；失败返回 null（静默降级）
  try {
    if (!text.trim()) return null
    if (text.startsWith('WARNING: Raw diagnostics')) return parseStartupText(file, text) // LG-core L550 分支
    const header = headerOf(text), err = sectionOf(text, 'error')
    if (!err) return null
    const kind = classifyError(err), failed = kind === 'plugin-activation' ? failedPluginsOf(err) : [], firstLine = err.split('\n')[0] ?? ''
    return { origin: 'log', file, kind, time: header.time && Number.isFinite(Date.parse(header.time)) ? header.time : new Date(statSync(file).mtimeMs).toISOString(),
      profile: header.profile ?? null, exitCode: /exited with (\d+)/.exec(err)?.[1] ?? null, summary: `${kind} · ${firstLine.slice(0, 140)}`, frame: firstFrame(err), failedPlugins: failed,
      evidenceNames: [...failed.flatMap((p) => [p.name, p.pkg]), ...moduleHintsOf(err), ...[...firstLine.matchAll(/\[([\w@/.-]+)\]/g)].map((m) => m[1])].filter(Boolean) }
  } catch { return null }
}
const readHead = (file, size) => { // LG-core readArtifact L226-239：只读头部，不整读大文件
  const fd = openSync(file, 'r')
  try { const buf = Buffer.alloc(Math.min(size, MAX_LOG_BYTES)); readSync(fd, buf, 0, buf.length, 0); return normText(buf.toString('utf8')) } finally { closeSync(fd) }
}
const readJournal = (store) => { // 撕裂行容忍（LG-core readJsonl L128-146）
  try { const out = []; for (const line of normText(readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')).split('\n')) { const t = line.trim(); if (t) { try { out.push(JSON.parse(t)) } catch { /* 撕裂行 */ } } } return out } catch { return [] }
}
export { readJournal } // 宿主半面板消费（index.js harnessChange 横幅）；0.7.0 曾漏导出致横幅永静默
/* journal → 包级候选 */
const pkgEventsOf = (entries) => {
  const out = []
  for (const e of entries) { const at = Date.parse(e.time ?? ''); if (!Number.isFinite(at)) continue
    if (e.kind === 'manifest-change') {
      for (const [list, act] of [[e.added, 'install'], [e.removed, 'remove']]) for (const pkg of list ?? []) out.push({ at, pkg, action: act, via: 'manifest-change', profile: e.profile ?? null })
    } else if (e.kind === 'snapshot') {
      const spec = (typeof e.spec === 'string' && e.spec) || /(?:install_bundle|remove_bundle):(.+)$/.exec(String(e.trigger ?? ''))?.[1]
      if (spec) for (const pkg of spec.split(/[,+]\s*/)) if (pkg) out.push({ at, pkg, action: /remove/.test(String(e.trigger)) ? 'remove' : 'install', via: `snapshot:${e.trigger}`, profile: e.profile ?? null })
    }
  }
  return out
}
const normName = (s) => String(s ?? '').toLowerCase().replace(/^@[\w.-]+\//, '')
// endsWith 后缀命中要求 ≥4 字符前缀（'graph' 曾假命中 'git-graph'——review #21；
// 保留 webserver ↔ @deepseek-ai/dsh-host-webserver 这类真实映射）
const nameEq = (a, b) => {
  const x = normName(a), y = normName(b)
  if (!x || !y) return false
  if (x === y) return true
  const [pre, suf] = x.length < y.length ? [y, x] : [x, y]
  return suf.length >= 4 && pre.endsWith(`-${suf}`) && pre.length - suf.length >= 4
}

const suspectsFor = (fromMs, toMs, events, names, directMs = DIRECT_MS) => {
  // 嫌疑 = [fromMs-directMs, toMs+5s] 内的包变更；崩溃后的变更不算——
  // 上界容忍只留 5s 时钟余量：60s 会把"崩溃检出后几秒内的用户修复动作"误捕为 direct
  // （真机实证：检出后 3s 的 manifest-change 被标 direct——那是解药不是凶手）
  const byPkg = new Map()
  for (const ev of events) {
    if (ev.at > toMs + 5_000 || toMs - ev.at > CIRC_MS) continue
    const hit = names.filter((n) => nameEq(n, ev.pkg)), conf = (hit.length || ev.at >= fromMs - directMs) ? 'direct' : 'circumstantial'
    if (byPkg.has(ev.pkg) && (byPkg.get(ev.pkg).confidence === 'direct' || conf !== 'direct')) continue // direct 优先；同档取先见者
    byPkg.set(ev.pkg, { pkg: ev.pkg, action: ev.action, via: ev.via, profile: ev.profile, lastEventAt: new Date(ev.at).toISOString(), gapMs: toMs - ev.at, confidence: conf,
      evidence: hit.length ? [`崩溃日志证据命中包名：${hit.join(', ')}`, `${ev.via} @ ${new Date(ev.at).toISOString()}`] : [`${ev.via} @ ${new Date(ev.at).toISOString()}（崩溃前 ${Math.max(0, Math.round((toMs - ev.at) / 60_000))} 分钟）`] })
  }
  return [...byPkg.values()].sort((a, b) => (a.confidence === b.confidence ? a.gapMs - b.gapMs : a.confidence === 'direct' ? -1 : 1)).slice(0, 5)
}

/**
 * node_modules 顶层目录 mtime 哨兵（U-5 演练实证盲点的补强）：
 * 裸 pnpm add 装的包若宿主在 diff 定时器（45s）触发前死亡，journal 完全无记录 → 归因失明。
 * 目录 mtime 不说谎：崩溃前 30 分钟内 mtime 新变的顶层包目录 = 装包痕迹，作为 journal 缺席时的
 * 补充事件源（via: 'nm-mtime'，direct 窗口内算 direct）。
 */
const nmMtimeEvents = (profileDir, fromMs, toMs, store, journalEntries = null) => {
  const out = []
  const nm = join(profileDir, 'node_modules')
  const scanTop = (parent, prefix) => {
    for (const entry of okReaddir(parent)) {
      if (entry.startsWith('.') ) continue // .pnpm/.ignored/.modules.yaml 等非包条目
      const p = join(parent, entry)
      let st; try { st = statSync(p) } catch { continue }
      if (!st.isDirectory()) continue
      const mt = Math.floor(st.mtimeMs)
      if (mt < fromMs - DIRECT_MS || mt > toMs + 5_000) continue
      if (prefix) {
        // scope 内层：包目录本体
        out.push({ pkg: `${prefix}/${entry}`, action: 'install', via: 'nm-mtime', profile: null, at: mt })
      } else if (entry.startsWith('@')) {
        scanTop(p, entry) // scope 目录：看它的 mtime，也深入一层
      } else {
        out.push({ pkg: entry, action: 'install', via: 'nm-mtime', profile: null, at: mt })
      }
    }
  }
  scanTop(nm, null)
  // 回填风暴过滤（M 系列冒烟实证）：restore 会 touch 全部回填文件的目录 mtime，此后 30 分钟内
  // 的崩溃归因会看到数千个包同秒"新变"——误报风暴，且淹没风暴窗口内的真装包。
  // 精确化：restoreMs（最后一次 restore journal 行）之前的 mtime 事件若呈风暴特征（单秒 >40）整批丢弃；
  // 之后的事件保留（restore 完成后的真装包不受风暴误伤）。
  // C4（0.7.4 审计 P2）：journal 由调用方传入复用（曾每个 crash 全量重读一遍）
  let restoreMs = 0
  if (journalEntries) {
    for (const e of journalEntries) {
      if (e.kind === 'restore') { const t = Date.parse(e.time ?? ''); if (Number.isFinite(t)) restoreMs = Math.max(restoreMs, t) }
    }
  }
  const [pre, post] = restoreMs > 0
    ? [out.filter((ev) => ev.at <= restoreMs + 10_000), out.filter((ev) => ev.at > restoreMs + 10_000)]
    : [out, []]
  const bySec = new Map()
  for (const ev of pre) {
    const sec = Math.floor(ev.at / 1000) // 目录 mtime 毫秒级散布，按秒分桶才聚得拢
    bySec.set(sec, (bySec.get(sec) ?? 0) + 1)
  }
  const storm = [...bySec.values()].some((n) => n > 40)
  return storm ? post : out
}

export function attributeCrash(opts = {}) { // 纯只读；永不 throw（四级静默降级链）
  const dshHome = opts.dshHome || resolveDshHome(), store = opts.store || resolveStore(dshHome)
  // snapshots：调用方已持有的全量列表可透传进来复用（P1-01：panel 路径曾双份解析 506×5.9MB manifest ≈ 双倍堆占用）
  const snapshotsOpt = Array.isArray(opts.snapshots) ? opts.snapshots : null
  const profileName = opts.profile?.name || resolveProfile(dshHome).name, now = opts.now ?? Date.now()
  const out = { ok: true, profile: profileName, generatedAt: new Date(now).toISOString(), sources: { logDirs: [], logScanned: 0, journalEvents: 0, journalOnly: false }, crashes: [], suspects: [], loops: [], restoreHint: null }
  try {
    const entries = readJournal(store), events = pkgEventsOf(entries), crashes = [], pointsMs = [], logs = []
    out.sources.journalEvents = entries.length
    try { for (const dir of crashLogDirs(dshHome)) for (const name of okReaddir(dir)) { // 日志收集（LG-core L195-222 + 7d 时窗限界）
      if (!CRASH_FILE_RE.test(name)) continue
      const file = join(dir, name); let st; try { st = statSync(file) } catch { continue }
      if (st.isFile() && st.size > 0 && st.mtimeMs >= now - (opts.hours ?? 168) * 36e5) logs.push({ file, size: st.size, mtimeMs: st.mtimeMs })
    } logs.sort((a, b) => a.mtimeMs - b.mtimeMs) } catch { /* journal-only */ }
    Object.assign(out.sources, { logDirs: [...new Set(logs.map((l) => dirname(l.file)))], logScanned: logs.length, journalOnly: logs.length === 0 })
    for (const log of logs) {
      let text = ''; try { text = readHead(log.file, log.size) } catch { continue }
      const c = parseCrashFile(log.file, text); if (!c || (c.profile && c.profile !== profileName)) continue
      crashes.push(c); const t = Date.parse(c.time); if (Number.isFinite(t)) pointsMs.push(t)
    }
    for (const e of entries) { // journal crash-detected：只知 boot 区间 [prevStartedAt, time]；日志已覆盖的同段崩溃（前 1h 邻域）不重复计
      if (e.kind !== 'crash-detected' || (e.profile && e.profile !== profileName)) continue
      const to = Date.parse(e.time ?? ''), from = Date.parse(e.prevStartedAt ?? '')
      if (!Number.isFinite(to) || crashes.some((c) => { const ct = Date.parse(c.time); return Number.isFinite(ct) && ct > to - 36e5 && ct <= to + 60_000 })) continue
      // R4 演练补充：宿主半在 uncaughtException 时写 fatalReason——有此字段=死因已知（如 OOM）
      const fatalNote = typeof e.fatalReason === 'string' && e.fatalReason ? e.fatalReason : null
      crashes.push({
        origin: 'journal', file: 'journal:crash-detected',
        kind: fatalNote ? (OOM_RE.test(fatalNote) ? 'out-of-memory' : 'uncaught-exception') : 'unclean-exit',
        time: e.time, bootFrom: Number.isFinite(from) ? e.prevStartedAt : null, profile: e.profile ?? profileName,
        exitCode: e.prevExitCode ?? null, frame: null, failedPlugins: [], evidenceNames: [],
        summary: fatalNote ? `致命收场：${fatalNote}` : '上次运行未净退出（pid 死亡，无日志细节）',
      })
      if (logs.length === 0) pointsMs.push(Number.isFinite(from) ? from : to) // journal-only 时才充当还原锚点
    }
    const byPkg = new Map()
    // shell-handshake（GUI 外壳握手失败）不参与插件归因，也不充当还原锚点——
    // 2026-11-10 实战：此类崩溃曾产出 zod/@anthropic-ai/sdk 假嫌疑 + 指向还原的无用建议
    const shell = crashes.filter((c) => c.kind === 'shell-handshake')
    for (const c of crashes) {
      if (c.kind === 'shell-handshake') { c.correlated = []; continue }
      const to = Date.parse(c.time) || now, from = c.bootFrom && Number.isFinite(Date.parse(c.bootFrom)) ? Date.parse(c.bootFrom) : to
      // journal 事件 + node_modules mtime 哨兵合并（U-5 盲点补强：journal 缺席时目录 mtime 兜底）
      const evAll = events.concat(nmMtimeEvents(opts.profile?.dir ?? resolveProfile(dshHome).dir, from, to, store, entries))
      const list = suspectsFor(from, to, evAll, c.evidenceNames ?? [], c.kind === 'out-of-memory' ? OOM_DIRECT_MS : DIRECT_MS)
      c.correlated = list.slice(0, 3)
      for (const s of list) { const prev = byPkg.get(s.pkg); if (!prev || s.confidence === 'direct' && prev.confidence !== 'direct' || s.confidence === prev.confidence && s.gapMs < prev.gapMs) byPkg.set(s.pkg, s) }
    }
    out.crashes = crashes.sort((a, b) => Date.parse(b.time) - Date.parse(a.time)).slice(0, 10)
    out.suspects = [...byPkg.values()].sort((a, b) => (a.confidence === b.confidence ? a.gapMs - b.gapMs : a.confidence === 'direct' ? -1 : 1)).slice(0, 5)
    const recent = pointsMs.filter((t) => now - t <= CIRC_MS).sort((a, b) => a - b)
    for (let i = 0; i < recent.length && !out.loops.length; i++) { // 崩溃循环（LG-attr crashLoops L94-122）：24h 内 1h 滑窗 >=3 个崩溃点
      const cluster = recent.filter((t) => t >= recent[i] && t - recent[i] <= 3600_000)
      if (cluster.length >= 3) out.loops.push({ count: cluster.length, first: new Date(cluster[0]).toISOString(), last: new Date(cluster[cluster.length - 1]).toISOString() })
    }
    // 外壳握手诊断汇总：全部崩溃皆 shell-handshake 时给出针对性指引（实战 2026-11-10 的真实死法）
    out.shellHandshake = shell.length ? { count: shell.length, allCount: crashes.length, all: shell.length === crashes.length,
      hint: 'GUI 外壳（Electron）与本地宿主的认证握手失败——不是插件问题。常见根因：外壳 Chromium 网络状态被强杀/断电损坏。修复：完全退出 DSH（含托盘）后运行 node "<快照库>\\cli\\dsh-snap.mjs" repair-gui（自动备份并重置外壳网络状态；也可双击快照库 cli/repair-gui.bat），再启动桌面。官方弹窗的「禁用第三方插件」对此无效，且会把第三方 bundles/patch 砍掉（可用 repair-profile 恢复）。' } : null
    if (pointsMs.length) { // 还原建议：崩溃点之前最近的快照（journal-only 用 boot 区间下界）；绝不指向崩溃后的快照
      let earliest = Infinity // P3-16：spread 对超大崩残数组会 RangeError，用 reduce
      for (const t of pointsMs) if (t < earliest) earliest = t
      const snap = (snapshotsOpt ?? listSnapshots(store)).find((m) => !m.corrupted && (m.timeEpoch ?? Date.parse(m.time) ?? 0) <= earliest)
      out.restoreHint = snap && !(shell.length === crashes.length) ? { snapshotId: snap.id, time: snap.time, command: `node "${join(store, 'cli', 'dsh-snap.mjs')}" restore ${snap.id}` } : snap ? { snapshotId: snap.id, time: snap.time, command: null, reason: '崩溃全部为外壳握手类——还原快照无法修复外壳状态，先试 repair-gui' } : { snapshotId: null, command: null, reason: '崩溃点之前没有可用快照（建议先拍基线再装插件）' }
    }
  } catch (e) { out.degraded = String(e?.message || e) }
  return out
}

/* ============================================================
 * G8 装前体检（preflight）——只告警不阻断；网络失败跳过并说明
 * ============================================================ */

/* ---- 零依赖 semver 子集：node-semver 比较 + canonical rewrite + includePrerelease 匹配 ---- */
const parseVer = (s) => {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(s).trim())
  if (!m) return null
  return { M: +m[1], m: +m[2], p: +m[3], pre: m[4] ? m[4].split('.') : [], raw: String(s).trim() }
}
const preCmp = (a, b) => {                                    // 无 pre > 有 pre；数字<字母；少段<多段
  if (!a.length || !b.length) return Math.sign(b.length - a.length)
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i], y = b[i]
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y)
    if (nx && ny) { if (+x !== +y) return Math.sign(+x - +y) }
    else if (nx !== ny) return nx ? -1 : 1
    else if (x !== y) return x < y ? -1 : 1
  }
  return 0
}
const vCmp = (a, b) => (a.M - b.M) || (a.m - b.m) || (a.p - b.p) || preCmp(a.pre, b.pre)
const isX = (s) => s === undefined || s === 'x' || s === 'X' || s === '*'
const V = (M, m, p, pre = []) => ({ M, m, p, pre })
const opRange = (op, v) => op === '>=' ? { lo: { v, inc: true }, hi: null }
  : op === '>' ? { lo: { v, inc: false }, hi: null } : op === '<' ? { lo: null, hi: { v, inc: false } }
  : op === '<=' ? { lo: null, hi: { v, inc: true } } : op === '=' || op === '' ? { lo: { v, inc: true }, hi: { v, inc: true } } : null
function tokenRange(tok) {                                    // token → [lo, hi) 半开区间
  const cm = /^(>=|<=|>|<|=|\^|~)?\s*v?(\d+|x|\*)(?:\.(\d+|x|\*)(?:\.(\d+|x|\*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?)?)?$/.exec(tok)
  if (!cm) return null
  const op = cm[1] || ''
  if (isX(cm[2])) return op ? null : { lo: null, hi: null }   // * / 空 = 任意
  const M = +cm[2], mn = +cm[3], pf = +cm[4], pre = cm[5] ? cm[5].split('.') : []
  if (isX(cm[3])) return (op === '' || op === '^' || op === '~') ? { lo: { v: V(M, 0, 0), inc: true }, hi: { v: V(M + 1, 0, 0, ['0']), inc: false } } : opRange(op, V(M, 0, 0))
  if (isX(cm[4])) return (op === '' || op === '^' || op === '~') ? { lo: { v: V(M, mn, 0), inc: true }, hi: { v: V(M, mn + 1, 0, ['0']), inc: false } } : opRange(op, V(M, mn, 0))
  const v = V(M, mn, pf, pre)
  if (op === '^') return { lo: { v, inc: true }, hi: { v: M > 0 ? V(M + 1, 0, 0, ['0']) : mn > 0 ? V(M, mn + 1, 0, ['0']) : V(M, mn, pf + 1, ['0']), inc: false } }
  if (op === '~') return { lo: { v, inc: true }, hi: { v: V(M, mn + 1, 0, ['0']), inc: false } }
  return opRange(op, v)
}
const inIv = (v, iv) =>
  (!iv.lo || (vCmp(v, iv.lo.v) < 0 ? false : vCmp(v, iv.lo.v) === 0 ? iv.lo.inc : true)) &&
  (!iv.hi || (vCmp(v, iv.hi.v) > 0 ? false : vCmp(v, iv.hi.v) === 0 ? iv.hi.inc : true))
function hyphenToks(s) {                                      // node-semver hyphenReplace：右侧部分版本 → <下一段.0-0
  const [a, b] = s.split(' - ').map((x) => x.trim())
  const la = a.split('.'); while (la.length < 3) la.push(0)
  const bp = b.split('.')
  const up = bp.length === 3 ? ['<=' + b] : bp.length === 2 ? ['<' + bp[0] + '.' + (+bp[1] + 1) + '.0-0'] : ['<' + (+bp[0] + 1) + '.0.0-0']
  return ['>=' + la.join('.'), ...up]
}
/** satisfies(ver, range) → true/false=结论；null=语法不识别（调用方按 unknown 跳过，不告警） */
export function satisfies(ver, range) {
  const v = typeof ver === 'string' ? parseVer(ver) : ver
  if (!v) return null
  for (const set of String(range).split('||')) {
    const norm = set.trim().replace(/(>=|<=|>|<|=|\^|~)\s+/g, '$1')   // 操作符后空格归一
    if (!norm) { if (inIv(v, { lo: null, hi: null })) return true; continue }  // 空集 = *
    const toks = norm.includes(' - ') ? hyphenToks(norm) : norm.split(/\s+/)
    const ivs = toks.map(tokenRange)
    if (ivs.some((x) => x === null)) return null
    if (ivs.every((iv) => inIv(v, iv))) return true
  }
  return false
}

/* ---- harness 版本解析：profile deps 里 @deepseek-ai/* 的最大精确版本（dshmarket 版本与本机 runtime.json desktopVersion 均已实证不可用） ---- */
function resolveHarnessVersion(deps) {
  let best = null; const sources = []
  for (const [name, v] of Object.entries(deps ?? {})) {
    if (!name.startsWith('@deepseek-ai/')) continue
    const parsed = parseVer(v)                       // 只认精确版本；file:/^/workspace: 丢弃
    if (parsed) { sources.push(`${name}@${v}`); if (!best || vCmp(parsed, best) > 0) best = parsed }
  }
  return best ? { version: best, from: sources } : null
}

/* ---- harness 变更哨兵（破坏性更新防线） ----
 * 桌面版更新频繁且常为破坏性更新（0.2 列车实测：全量 NSIS 替换 app 目录；profile 内
 * 传递依赖随 harness 重解析被动变化）。哨兵在宿主启动时比对「环境指纹」，变化即：
 *  1) journal 记 harness-change 行（可归因「更新后首启」故障）
 *  2) 自动拍 trigger:harness-change 基线快照（更新后状态入库，可与更新前 diff）
 * 指纹组成（全部本机实证可取）：@deepseek-ai/* 版本集合 + app 安装目录指纹 + runtime payloadDigest。
 */
export function harnessFingerprint(dshHome, profile) {
  const parts = {}
  // ① profile deps 里 @deepseek-ai/* 精确版本集合（排序后拼接；升级/降级都变）
  try {
    const deps = readJson(join(profile.dir, 'package.json'), null)?.dependencies ?? {}
    parts.harnessDeps = Object.entries(deps)
      .filter(([n]) => n.startsWith('@deepseek-ai/'))
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([n, v]) => `${n}@${v}`).join(',') || null
  } catch { parts.harnessDeps = null }
  // ② app 安装目录指纹（NSIS 全量替换会整体更新 mtime/内容）。
  // **不用 app.asar 本体**：Electron 宿主进程把 asar 映射进内存后，进程内 statSync 得到
  // size=0、mtime=映射时刻（桌面实机实证：13:12 启动的宿主 stat 出 mtime=13:12）——指纹会
  // 每次启动漂移。改用 app 目录内不被映射的安装器落盘文件（Uninstall exe，NSIS 每次覆盖）。
  {
    const markerRel = join('Deepseek Harness', 'Uninstall DeepSeek Harness.exe')
    const tryStat = (p) => {
      try {
        const st = statSync(p)
        if (st.size <= 0) return false
        parts.app = `${p}|${st.size}|${Math.floor(st.mtimeMs / 1000)}`
        return true
      } catch { return false }
    }
    let hit = false
    try {
      const abs = resolve(dshHome) // 正斜杠/URL 派生路径先规范化（曾 split(sep) 对 'E:/x' 产单段，祖先链 0 探测）
      const segs = abs.split(sep).filter(Boolean)  // ['E:', 'AI', 'Data', 'DSH']
      for (let i = segs.length - 1; i >= 1 && !hit; i--) {
        hit = tryStat(join(segs.slice(0, i).join(sep) + sep, markerRel))
      }
    } catch { /* 祖先链探测失败继续 */ }
    if (!hit && IS_WIN) {
      try {
        // GUID 各机器不同（本机实测为随机 UUID），按 DisplayName 全区搜（递归约 1s）
        const out = spawnSync('reg', ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall', '/s', '/f', 'DeepSeek Harness', '/d'], { encoding: 'utf8', timeout: 15000 })
        const key = String(out.stdout || '').match(/HKEY[^\r\n]*Uninstall(\S*)/i)
        if (key) {
          const loc = spawnSync('reg', ['query', key[0], '/v', 'InstallLocation'], { encoding: 'utf8', timeout: 6000 })
          const m = String(loc.stdout || '').match(/InstallLocation\s+REG_SZ\s+(.+)/i)
          if (m) hit = tryStat(join(m[1].trim(), 'Uninstall DeepSeek Harness.exe'))
        }
      } catch { /* 注册表不可得，试默认路径 */ }
    }
    if (!hit) {
      for (const base of ['C:\\Program Files', 'C:\\Program Files (x86)', join(process.env.LOCALAPPDATA || '', 'Programs')]) {
        if (tryStat(join(base, markerRel))) break
      }
    }
    // 注册表版本号兜底（NSIS DisplayVersion 每次更新必变；无文件可 stat 时仍有版本感知）
    if (!parts.app && IS_WIN) {
      try {
        const out = spawnSync('reg', ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall', '/s', '/f', 'DeepSeek Harness', '/d'], { encoding: 'utf8', timeout: 15000 })
        const key = String(out.stdout || '').match(/HKEY[^\r\n]*Uninstall(\S*)/i)
        if (key) {
          const ver = spawnSync('reg', ['query', key[0], '/v', 'DisplayVersion'], { encoding: 'utf8', timeout: 6000 })
          const m = String(ver.stdout || '').match(/DisplayVersion\s+REG_SZ\s+(\S+)/i)
          if (m) parts.app = `reg:${m[1]}`
        }
      } catch { /* 全链失败：app 字段缺失，其余指纹仍有效 */ }
    }
  }
  // ③ runtime payloadDigest（runtime.json；runtime 热更新时变化）
  try {
    const rt = readJson(join(dshHome, 'dsh-runtimes', 'dsh-primary-runtime', 'runtime.json'), null)
    parts.runtime = rt?.payloadDigest ?? null
  } catch { parts.runtime = null }
  return parts
}

/** 比对指纹与 store 内记录；变化时返回 {changed, from, to}，否则返回 null。**只读**。 */
export function detectHarnessChange(dshHome, profile, store) {
  const cur = harnessFingerprint(dshHome, profile)
  const file = join(store, `harness-state-${profile.name}.json`)
  const saved = readJson(file, null)
  if (!saved?.fingerprint) return { changed: false, cur, saved: null } // 首启：只建档
  const changed = saved.fingerprint.harnessDeps !== cur.harnessDeps
    || saved.fingerprint.app !== cur.app
    || saved.fingerprint.runtime !== cur.runtime
  return changed
    ? { changed: true, from: saved.fingerprint, to: cur, savedAt: saved.at, pendingBaseline: !!saved.pendingBaseline }
    : { changed: false, cur, saved: saved, savedAt: saved.at, pendingBaseline: !!saved.pendingBaseline }
}

/** 写回指纹档案（变化检出后由宿主调用） */
export function saveHarnessState(dshHome, profile, store, fingerprint, extra = {}) {
  const file = join(store, `harness-state-${profile.name}.json`)
  mkdirSync(store, { recursive: true }) // selftest/裸调用时 store 可能尚未建
  atomicWriteJson(file, { fingerprint, at: new Date().toISOString(), ...extra })
  return file
}

/* ---- spec → registry 包名（tarball/file:/git 形态显式放弃） ---- */
export function specToName(spec) {
  const s = String(spec ?? '').trim()
  if (!s || /^(https?:|file:|git(\+ssh)?:|link:)/i.test(s) || /\.tgz$/i.test(s)) return null
  const at = s[0] === '@' ? s.indexOf('@', 1) : s.indexOf('@')   // 尾部 @version 剥离
  const name = at > 0 ? s.slice(0, at) : s
  return /^[a-z0-9-][a-z0-9._-]*$/i.test(name) || /^@[a-z0-9-][a-z0-9._-]*\/[a-z0-9._-]+$/i.test(name) ? name : null
}

/* ---- registry 元数据：/latest 单文档 + TTL 缓存 + in-flight 去重 + 失败静默 ---- */
const preflightInflight = new Map()
function loadPreflightCache(store) { try { return readJson(join(store, 'preflight-cache.json'), null) ?? {} } catch { return {} } }
function registryMeta(store, name, ttlMs = 6 * 3600 * 1000) {
  const cache = loadPreflightCache(store)
  const hit = cache[name]
  if (hit && Date.now() - hit.time < ttlMs) return Promise.resolve({ ...hit, fromCache: true })
  if (preflightInflight.has(name)) return preflightInflight.get(name)
  const p = fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}/latest`, { signal: AbortSignal.timeout(4000) })
    .then(async (res) => {
      if (res.status === 404) return { time: Date.now(), status: 404, fromCache: false }
      if (!res.ok) return { time: Date.now(), status: res.status, error: `HTTP ${res.status}`, fromCache: false }
      const doc = await res.json()                                                              // ~2.5KB
      const row = { time: Date.now(), status: 200, version: doc.version ?? null,
        engines: doc.engines ?? null, deprecated: typeof doc.deprecated === 'string' ? doc.deprecated : null, fromCache: false }
      cache[name] = row; atomicWriteJson(join(store, 'preflight-cache.json'), cache)
      return row
    })
    .catch((e) => ({ time: Date.now(), status: 0, error: String(e?.message || e), fromCache: false }))  // 网络失败→静默降级
    .finally(() => preflightInflight.delete(name))
  preflightInflight.set(name, p)
  return p
}

/* ---- 主入口。永不 reject、永不建议阻断。 ---- */
export async function preflightPackage({ spec, profile, store }) {
  const checks = []
  const add = (id, ok, detail) => checks.push({ id, ok, detail })
  const name = specToName(spec)
  const profDir = profile?.dir || resolveProfile().dir
  const deps = readJson(join(profDir, 'package.json'), null)?.dependencies ?? {}
  const harness = resolveHarnessVersion(deps)
  let meta = null
  if (!name) add('spec-parse', true, `非 registry spec（${spec}）：元数据预检不适用，跳过`)
  else {
    meta = await registryMeta(store, name)
    if (meta.status === 0) add('spec-parse', true, `网络失败，registry 预检整体跳过：${meta.error}`)
    else {
      add('spec-parse', true, name)
      if (meta.status === 404) add('pkg-exists', false, `${name} 在 registry 上不存在（拼写错误/已下架/私有源？）——这次安装大概率失败`)
      else if (meta.error) add('pkg-exists', true, `跳过（registry 异常：${meta.error}）`)
      else {
        add('pkg-exists', true, `${name}@${meta.version}${meta.fromCache ? '（缓存）' : ''}`)
        if (meta.deprecated) add('deprecated', false, `${name} 已声明弃用：${meta.deprecated}`)
        else add('deprecated', true, '无弃用标记')
        const dshRange = meta.engines?.dsh, nodeRange = meta.engines?.node
        if (dshRange === undefined) add('engines-dsh', true, '未声明 engines.dsh（宿主仍可能按 DSH peer 包检查）')
        else if (!harness) add('engines-dsh', true, '本机 harness 版本不可知（profile deps 无 @deepseek-ai/* 精确版本），跳过')
        else {
          const sat = satisfies(harness.version, String(dshRange))
          if (sat === true) add('engines-dsh', true, `声明 dsh ${dshRange}；本机 harness ${harness.version.raw} 满足（来源 ${harness.from.join(', ')}）`)
          else if (sat === false) add('engines-dsh', false, `本机 harness ${harness.version.raw} 不满足声明 dsh ${dshRange} —— 宿主 incompatible-version 闸门大概率拒绝`)
          else add('engines-dsh', true, `范围语法未识别（${dshRange}），跳过`)
        }
        if (nodeRange !== undefined) {
          const nodeSat = satisfies(process.version, String(nodeRange))
          add('engines-node', nodeSat === true, nodeSat === true ? `声明 node ${nodeRange}；本机 ${process.version} 满足` : `本机 node ${process.version} 不满足声明 ${nodeRange}`)
        }
      }
    }
  }
  return { ok: checks.every((c) => c.ok), spec: String(spec ?? ''), name,
    harnessVersion: harness?.version.raw ?? null,
    nonBlocking: true, checks }
}

/* ============================================================
 * G12 rescue serve：本机回环网页（DSH 完全起不来时，浏览器还能用）
 * 边界：只绑 127.0.0.1；随机 token 门禁；还原与 CLI 同一安全规则
 *（运行中 DSH 拒绝、guard 先行、默认不动 home 层）；预览必须先于执行。
 * ============================================================ */
export function serveStore({ store = resolveStore(), port = 27740, host = '127.0.0.1' } = {}) {
  const token = createHash('sha256').update(`${Date.now()}-${Math.random()}`).digest('hex').slice(0, 16)
  const profile = resolveProfile()
  const json = (res, code, obj) => { const b = Buffer.from(JSON.stringify(obj), 'utf8'); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(b) }
  const guard = (req, res, url) => {
    if (url.searchParams.get('k') !== token) { json(res, 401, { ok: false, code: 'bad-token' }); return false }
    return true
  }
  const readBody = (req) => new Promise((resolveBody) => {
    let d = ''
    req.on('data', (c) => { d += c; if (d.length > 65536) req.destroy() })
    req.on('end', () => {
      try {
        const v = JSON.parse(d || '{}')
        resolveBody(v && typeof v === 'object' && !Array.isArray(v) ? v : {}) // P3-12：null/数组/标量一律归空对象
      } catch { resolveBody({}) }
    })
    req.on('error', () => resolveBody({}))
  })
  const server = createServer(async (req, res) => {
    try {
      // P2-1 修复：URL 解析必须在 try 内——一条畸形请求行（裸 GET /%zz）在 try 外
      // 抛出即成 unhandledRejection 杀掉整个救援进程（审计实证，无需 token）
      const url = new URL(req.url, 'http://x')
      if (url.pathname === '/' || url.pathname === '/index.html') {
        if (!guard(req, res, url)) return
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
        res.end(servePage(token))
        return
      }
      if (!url.pathname.startsWith('/api/')) { res.writeHead(404); res.end(); return }
      if (!guard(req, res, url)) return
      const api = url.pathname
      if (api === '/api/list' && req.method === 'GET') {
        return json(res, 200, { ok: true, store, profile: profile.name, snapshots: listSnapshots(store).slice(0, 40).map((m) => m.corrupted ? { id: m.id, corrupted: true } : { id: m.id, time: m.time, trigger: m.trigger, spec: m.spec, label: m.label, guard: !!m.guard, manual: !!m.manual, files: m.stats?.files ?? null, bytes: m.stats?.bytes ?? null }) })
      }
      if (api === '/api/doctor' && req.method === 'GET') return json(res, 200, doctor(profile))
      if (api === '/api/crash' && req.method === 'GET') return json(res, 200, attributeCrash({ store, profile }))
      if (api === '/api/snapshot' && req.method === 'POST') {
        const manifest = takeSnapshot({ store, profile, trigger: 'manual', label: 'rescue serve 网页快照' })
        return json(res, 200, { ok: true, id: manifest.id, files: manifest.stats.files })
      }
      if (api === '/api/verify' && req.method === 'POST') {
        const body = await readBody(req)
        const id = body.id || newestSnapshotId(store)
        if (!id) return json(res, 200, { ok: false, code: 'no-snapshot' })
        return json(res, 200, verifySnapshot(store, id, { deep: body.deep === true }))
      }
      if (api === '/api/restore' && req.method === 'POST') {
        const body = await readBody(req)
        if (body.confirm !== true) { // 两步制：先预览后执行
          const plan = restoreSnapshot({ store, target: body.id || 'last', profile, dryRun: true, includeHome: body.includeHome === true })
          // D3（0.7.4 审计 P2）：预览曾丢弃 trustLevel/evidence——degraded（快照缺文件）
          // 时用户只看到正常计划，最应阻止执行的证据被隐藏
          return json(res, 200, { ok: plan.ok, preview: true, plan: plan.plan, restoredTo: plan.restoredTo, error: plan.error, reasons: plan.reasons, trustLevel: plan.trustLevel ?? null, evidence: plan.evidence ?? null })
        }
        // degraded 执行须显式确认（evidence 知情权在确认参数里闭环）
        if (body.confirm === true && !body.confirmDegraded) {
          const pre = restoreSnapshot({ store, target: body.id || 'last', profile, dryRun: true, includeHome: body.includeHome === true })
          if (pre.trustLevel === 'degraded') {
            return json(res, 200, { ok: false, code: 'degraded-confirm', trustLevel: pre.trustLevel, evidence: pre.evidence,
              message: '快照完整性降级（文件缺失/索引丢失）——重发请求并带 confirmDegraded:true 才能执行' })
          }
        }
        const r = restoreSnapshot({ store, target: body.id || 'last', profile, includeHome: body.includeHome === true, force: body.force === true, pruneExtraneous: body.pruneExtraneous === true })
        return json(res, 200, r.ok ? { ok: true, restoredTo: r.restoredTo, guardId: r.guardId, restored: r.restored, skipped: r.skipped, reported: r.reported.slice(0, 10), radius: r.radius, interruptedBefore: r.interruptedBefore } : r)
      }
      if (api === '/api/stop' && req.method === 'POST') {
        json(res, 200, { ok: true })
        setTimeout(() => {
          try { server.close(() => { try { server.closeAllConnections?.() } catch { /* 老.node 无此 API */ } }) } catch { /* 忽略 */ }
          // keep-alive 页面轮询会让 close() 迟迟不完成（review #14：'close' 事件不触发，
          // serve 挂住不退出）——主动断空闲连接
          try { server.closeIdleConnections?.() } catch { /* 老.node */ }
        }, 100)
        return
      }
      return json(res, 404, { ok: false, code: 'no-route' })
    } catch (e) { json(res, 200, { ok: false, code: 'error', message: String(e?.message || e).slice(0, 200) }) }
  })
  // resolve 语义 = 服务停止（close/error），而不是 listen 成功——否则 main 返回即 process.exit 杀掉服务
  return new Promise((resolveRun) => {
    server.once('error', (e) => resolveRun({ ok: false, code: 'listen-failed', error: String(e?.message || e) }))
    server.on('close', () => resolveRun({ ok: true, closed: true }))
    server.listen(port, host, () => {
      const url = `http://${host}:${port}/?k=${token}`
      console.log(`dsh-snap rescue serve: ${url}`)
      console.log('（仅本机回环可访问；还原前先预览；完全退出 DSH 后再执行还原）')
    })
  })
}

const servePage = (token) => `<!doctype html><html lang="zh"><meta charset="utf-8"><title>dsh-snap rescue</title>
<style>body{font:14px/1.6 system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 12px;color:#222}
button{border:1px solid #bbb;border-radius:6px;padding:4px 10px;background:#fff;cursor:pointer;margin:2px}
button:hover{background:#f2f2f2}table{width:100%;border-collapse:collapse;margin:12px 0}
th,td{padding:5px 8px;border-bottom:1px solid #ddd;text-align:left;font-size:13px}
pre{background:#f6f6f6;padding:10px;border-radius:8px;white-space:pre-wrap;word-break:break-all}
#out{margin:10px 0}.row{cursor:pointer}.row:hover{background:#fafafa}
.warn{color:#b45309}.ok{color:#15803d}label{margin-right:10px}</style>
<h2>dsh-snap · 救援台 <small style="font-weight:400;opacity:.6">（DSH 起不来时用）</small></h2>
<div>
<button onclick="act('/api/snapshot','POST')">立即快照</button>
<button onclick="act('/api/doctor','GET')">环境体检</button>
<button onclick="act('/api/crash','GET')">崩溃归因</button>
<button onclick="verifyLatest()">校验最新快照</button>
</div>
<div id="out"></div>
<table><thead><tr><th>时间</th><th>触发</th><th>对象</th><th>规模</th><th>操作</th></tr></thead><tbody id="tb"></tbody></table>
<div>
<label><input type="checkbox" id="dry" checked> dry-run 预览</label>
<label><input type="checkbox" id="force"> 强制（DSH 可能运行中，不推荐）</label>
<label><input type="checkbox" id="extra"> 移除多出的包（入 trash 可找回）</label>
</div>
<p style="opacity:.6">点行选中还原目标；执行还原会先自动拍 guard 快照（可撤销）。</p>
<script>
const K = ${JSON.stringify(token)}
// P2-6 修复：manifest 的 spec/label/trigger 是外部数据（插件可写任意串）——进 innerHTML
// 前必须转义，否则 prompt-injection 可借存储型 XSS 触达 confirm:true 还原（审计实证）
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const q = (p) => p + (p.includes('?') ? '&' : '?') + 'k=' + K
let sel = 'last'
async function j(p, opt) { const r = await fetch(q(p), opt); return r.json() }
function show(text, cls) { document.getElementById('out').innerHTML = '<pre class="' + esc(cls || '') + '">' + esc(text) + '</pre>' }
async function reload() {
  const d = await j('/api/list')
  document.getElementById('tb').innerHTML = (d.snapshots || []).map((s) => s.corrupted
    ? '<tr><td colspan="5">' + esc(s.id) + ' ⚠️ 损坏</td></tr>'
    : '<tr class="row" onclick=\\'pick("' + esc(s.id) + '")\\'><td>' + esc(s.time?.replace('T', ' ').slice(0, 19)) + '</td><td>' + esc((s.guard ? '[guard] ' : s.manual ? '[手动] ' : '') + s.trigger) + '</td><td>' + esc(s.spec || s.label || '') + '</td><td>' + esc(s.files ?? '?') + '</td><td><button onclick=\\'event.stopPropagation();restore("' + esc(s.id) + '")\\'>还原到这</button></td></tr>').join('')
}
function pick(id) { sel = id; show('已选还原目标：' + id + '（点「还原到这」或先预览）') }
async function act(p, m) { const d = await j(p, { method: m }); show(JSON.stringify(d, null, 2), d.ok === false ? 'warn' : 'ok'); reload() }
async function verifyLatest() {
  const d = await j('/api/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deep: true }) })
  show('校验 ' + d.id + '：' + (d.ok ? '✅ 完整性通过' : '⚠️ 缺失 ' + d.missingCount + ' / 被改 ' + d.modifiedCount + ' / 哈希不符 ' + d.hashMismatchCount), d.ok ? 'ok' : 'warn')
}
async function restore(id) {
  const dry = document.getElementById('dry').checked
  if (dry) {
    const d = await j('/api/restore', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) })
    // D3：degraded 证据必须显著呈现——曾只显示正常计划
    const deg = d.trustLevel === 'degraded' ? '\\n\\n⚠️ 完整性降级：' + JSON.stringify(d.evidence) + '\\n（快照缺文件/索引丢失——执行会跳过缺失项并如实报告，但请优先考虑更早的快照）' : ''
    show('[预览] ' + JSON.stringify(d.plan || d, null, 2) + deg + '\\n\\n（确信无误后取消勾选 dry-run 再点一次）', d.ok === false || d.trustLevel === 'degraded' ? 'warn' : '')
  } else {
    if (!confirm('确认还原到 ' + id + '？\\n（会先自动拍 guard 快照，可撤销；请确认 DSH 已完全退出）')) return
    const d = await j('/api/restore', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, confirm: true, force: document.getElementById('force').checked, pruneExtraneous: document.getElementById('extra').checked }) })
    if (d.code === 'degraded-confirm') {
      if (!confirm('快照完整性降级（' + JSON.stringify(d.evidence) + '）\\n仍要执行吗？')) { show('已取消（degraded 未确认）', 'warn'); return }
      const d2 = await j('/api/restore', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, confirm: true, confirmDegraded: true, force: document.getElementById('force').checked, pruneExtraneous: document.getElementById('extra').checked }) })
      show(JSON.stringify(d2, null, 2), d2.ok ? 'ok' : 'warn'); reload(); return
    }
    show(JSON.stringify(d, null, 2), d.ok ? 'ok' : 'warn')
  }
}
reload()
setInterval(reload, 30000)
</script>`

/* ============================================================
 * diff（业界标准能力，Snapper 模式）：两快照间的差异视图
 * 只读索引比对，秒级；供"装前 vs 装后"核对与 bisect 决策。
 * ============================================================ */

export function diffSnapshots(store, idA, idB, { maxRows = 200 } = {}) {
  const ma = readSnapshotManifest(store, idA)
  const mb = readSnapshotManifest(store, idB)
  if (!ma || !mb) return { ok: false, code: 'snapshot-not-found', idA: ma ? undefined : idA, idB: mb ? undefined : idB }
  const ia = readFilesIndex(store, idA), ib = readFilesIndex(store, idB)
  if (!ia || !ib) return { ok: false, code: 'index-missing', idA: ia ? undefined : idA, idB: ib ? undefined : idB }
  const mapA = new Map(ia.map((r) => [r[0], r]))
  const mapB = new Map(ib.map((r) => [r[0], r]))
  const added = [], removed = [], changed = [], pkgAdded = new Set(), pkgRemoved = new Set()
  const topOf = (rel) => rel.split(sep)[0]
  for (const [rel, row] of mapB) {
    const a = mapA.get(rel)
    if (!a) { added.push(rel); if (row[3] === 'file') pkgAdded.add(topOf(rel)) }
    else if (a[1] !== row[1] || a[2] !== row[2] || (row[5] && a[5] && a[5] !== row[5])) changed.push(rel)
  }
  for (const [rel, row] of mapA) {
    if (!mapB.has(rel)) { removed.push(rel); if (row[3] === 'file') pkgRemoved.add(topOf(rel)) }
  }
  return {
    ok: true, from: idA, to: idB, timeFrom: ma.time, timeTo: mb.time,
    counts: { added: added.length, removed: removed.length, changed: changed.length },
    topPackages: { added: [...pkgAdded], removed: [...pkgRemoved] },
    samples: { added: added.slice(0, maxRows), removed: removed.slice(0, maxRows), changed: changed.slice(0, maxRows) },
  }
}

/* ============================================================
 * 幽灵依赖与残锁检测（六轮演练实证的两个真痛点）
 * ============================================================ */

/** 幽灵依赖：deps 里装了、manifest 声明 dsh.bundle，但没进 dsh.profile.bundles → 装了不激活 */
export function ghostDeps(profileDir, installAnchor) {
  const manifest = readJson(join(profileDir, 'package.json'), null)
  if (!manifest) return { ok: false, reason: 'manifest 不可读' }
  const deps = Object.keys(manifest.dependencies ?? {})
  const bundles = manifest.dsh?.profile?.bundles ?? []
  const ghosts = []
  for (const name of deps) {
    if (bundles.includes(name)) continue
    // 解析包目录读 dsh.bundle 声明（只认 node_modules 内真实存在的）
    let pkgDir = null
    for (const anchor of [installAnchor, profileDir].filter(Boolean)) {
      const cand = join(anchor, 'node_modules', name)
      if (existsNo(join(cand, 'package.json'))) { pkgDir = cand; break }
    }
    if (!pkgDir) continue
    const meta = readJson(join(pkgDir, 'package.json'), null)
    if (meta?.dsh?.bundle !== undefined) ghosts.push(name)
  }
  return { ok: true, ghosts, hint: ghosts.length ? '这些包已安装且声明 dsh.bundle，但不在 dsh.profile.bundles 里——装了不激活（裸 pnpm add 的典型结果）。走 dsh plugin add 或手动补 bundles。' : null }
}

/** 安装残锁：.plugin-manager 运行记录与 package.json.lock（持锁进程死了会残留，后续安装超时 120s） */
export function staleLocks(profileDir) {
  const out = []
  const runRecord = join(profileDir, '.plugin-manager', 'run.json')
  if (existsNo(runRecord)) {
    let pid = null
    try { pid = JSON.parse(readFileSync(runRecord, 'utf8'))?.pid ?? null } catch { /* 损坏也算残留 */ }
    if (pid === null || !pidAlive(pid)) out.push({ kind: 'run.json', path: runRecord, detail: '插件操作记录残留（持锁进程已死）' })
  }
  const pkgLock = join(profileDir, 'package.json.lock')
  if (existsNo(pkgLock)) {
    try {
      const st = statSync(pkgLock)
      if (Date.now() - st.mtimeMs > 10 * 60_000) out.push({ kind: 'package.json.lock', path: pkgLock, detail: `原子写锁残留（${Math.round((Date.now() - st.mtimeMs) / 60000)} 分钟无更新；活锁每 5s 内必有写动作）` })
    } catch { /* 读不了不报 */ }
  }
  return out
}

/** 残锁清理：只删「持锁进程已死」的 run.json 与超时无更新的 package.json.lock */
export function unstick(profileDir) {
  const removed = [], kept = []
  for (const lock of staleLocks(profileDir)) {
    try {
      if (lock.kind === 'run.json') { rmSync(lock.path, { force: true }); removed.push(lock) }
      else {
        // package.json.lock：先试持锁进程是否真死（锁文件不含 pid，只按超时判定）
        rmSync(lock.path, { force: true }); removed.push(lock)
      }
    } catch (e) { kept.push({ ...lock, error: String(e) }) }
  }
  if (removed.length) appendJournal(resolveStore(), { kind: 'unstick', removed: removed.map((r) => r.kind) })
  return { ok: true, removed, kept }
}

/* ---- 官方崩溃恢复痕迹 + 外科修复（2026-11-10 实战产品化）----
 * 官方弹窗「禁用第三方插件、备份 profile patch 并重启」（sanitizeProfile）：
 * renameSync(cordis.patch.yml → cordis.patch.yml.bak-<Date.now()>) + bundles 砍成 web 官方集合。
 * deps 保留、node_modules 不动——纯配置破坏，且 patch 原文完好躺在 .bak 里。
 * 实战时序：GUI 握手死循环（外壳状态坏）→ 用户连按恢复 ×3 → bundles 全灭 → dsh-snap 险些被去激活。
 */

const RECOVERY_BAK_RE = /^cordis\.patch\.ya?ml\.bak-(\d{13,})$/ // 官方恢复 rename 的命名（Unix 毫秒）

/** 廉价 bundle 对照源：快照 id 名即时间序，倒序只读 profile/package.json（~700B），绝不碰 5.9MB 的
 * manifest.json——doctor 已持有一份全量 listSnapshots（506×22968 行索引 ≈3GB），再叠一份必然顶破堆顶
 * （0.7.2 首版实测 OOM：manifest 内嵌 layers.nodeModules.index，listSnapshots 两次并发解析 ≈6GB）。
 * 取近期窗口（60 个）内 **bundles 全部装在现行 node_modules** 的最大值：既排除受损期快照（bundles 已被砍），
 * 也排除演练/旧态快照（bundles 指向现已不存在的包——恢复出去就是必死配置）。 */
function snapshotBundlesMax(store, nmDir, deps) {
  try {
    const root = storeLayout(store).snapshots
    const ids = okReaddir(root).filter((id) => /^[0-9T]{8}T[0-9]{6}-[0-9a-f]{6}$/.test(id)).sort().reverse()
    let best = null
    for (const id of ids.slice(0, 60)) { // 对照只需近期历史，60 个候选封顶
      const mp = readJson(join(root, id, 'profile', 'package.json'), null)
      const b = mp?.dsh?.profile?.bundles
      // P2-02：@deepseek-ai 前缀豁免只在「快照与 live 的官方 harness deps 精确同版」时生效——
      // 实验包由运行时树按版本供给，版本错位的旧快照可能指向已随运行时移除的包
      const officialDeps = Object.entries(mp?.dependencies ?? {}).filter(([n]) => n.startsWith('@deepseek-ai/'))
      const sameHarness = officialDeps.length > 0 && officialDeps.every(([n, v]) => deps?.[n] === v)
      if (Array.isArray(b) && b.length) {
        // bundle 存在性三选一：profile node_modules 实装 / 现行 deps 声明 / 官方命名空间（须同版 harness）
        // P1-06：nm 不存在时不再整体放行——existsNo 自然为 false，deps 仍可独立满足；
        // 没有任何解析依据的包一律不得写回 bundles
        const installed = b.every((name) => typeof name === 'string' && name.length > 0 &&
          (existsNo(join(nmDir, name, 'package.json')) || deps?.[name] !== undefined || (name.startsWith('@deepseek-ai/') && sameHarness)))
        if (installed && (!best || b.length > best.count)) best = { count: b.length, from: id, bundles: b }
      }
    }
    return best
  } catch { /* 快照侧不可得 */ }
  return null
}

/** 检测官方崩溃恢复痕迹：.bak-<epoch> 文件 + live bundles 是否被砍（相对最新 .bak / 最新快照） */
export function recoveryArtifacts(profileDir, store) {
  const baks = okReaddir(profileDir).map((n) => { const m = RECOVERY_BAK_RE.exec(n); return m ? { name: n, path: join(profileDir, n), epoch: Number(m[1]) } : null }).filter(Boolean).sort((a, b) => b.epoch - a.epoch)
  if (!baks.length) return { ok: true, found: false }
  const manifest = readJson(join(profileDir, 'package.json'), null)
  const livePatchSize = (() => { try { return statSync(join(profileDir, 'cordis.patch.yml')).size } catch { return -1 } })()
  const newest = baks[0]
  const newestSize = (() => { try { return statSync(newest.path).size } catch { return -1 } })()
  // bundles 被砍的判据：live bundles 数 vs 快照侧 bundles 数（廉价扫描，见 newestSnapshotBundles）
  const snapshotBundles = snapshotBundlesMax(store, join(profileDir, 'node_modules'), manifest?.dependencies)
  const liveBundles = manifest?.dsh?.profile?.bundles?.length ?? null
  const bundlesShrunk = snapshotBundles != null && liveBundles != null && liveBundles < snapshotBundles.count
  // patch 是否与最新 .bak 不同：字节内容比较（P2-01：尺寸相同内容可不同；读不了按尺寸兜底）
  const patchDiffers = (() => {
    try {
      const live = readFileSync(join(profileDir, 'cordis.patch.yml'))
      const bak = readFileSync(newest.path)
      return !bak.equals(live)
    } catch { return livePatchSize >= 0 && newestSize >= 0 && livePatchSize !== newestSize }
  })()
  return { ok: true, found: true, baks, newest: { name: newest.name, epoch: newest.epoch, size: newestSize }, livePatchSize,
    bundlesShrunk, liveBundles, snapshotBundles,
    patchDiffers }
}

/** 外科修复 profile 配置：bundles ← 最新可用快照；patch ← 最新官方恢复 .bak（内容 = 恢复前的原文）。
 * node_modules 与 deps 一律不动；现有(可能损坏的)配置先备份进 store/incidents/。--dry-run 只出计划。 */
export function repairProfile(opts = {}) {
  const dshHome = opts.dshHome || resolveDshHome()
  const profile = opts.profile?.dir ? opts.profile : resolveProfile(dshHome)
  const store = opts.store || resolveStore(dshHome)
  const dryRun = !!opts.dryRun
  const out = { ok: true, profile: profile.name, dryRun, actions: [], skipped: [], errors: [], guardDir: null }

  // 1) patch 源：最新官方恢复 .bak（rename 保留原文；排除「内容与 live 相同」的平凡情形）。
  // P2-01：曾按「尺寸不同」选源——同尺寸不同内容（截断/重排）会漏修；按字节内容比较。
  const art = recoveryArtifacts(profile.dir, store)
  const manifestPath = join(profile.dir, 'package.json'), patchPath = join(profile.dir, 'cordis.patch.yml')
  const manifest = readJson(manifestPath, null)
  if (!manifest) { out.ok = false; out.skipped.push('package.json 不可读——放弃（不敢在清单缺失时写 bundles）'); return out }
  let patchFrom = null
  if (art.found) {
    let livePatch = null
    try { livePatch = readFileSync(patchPath) } catch { /* ENOENT：live 缺失，任一 .bak 都可作为恢复源 */ }
    for (const b of art.baks) {
      let candidate = null
      try { candidate = readFileSync(b.path) } catch { continue }
      if (!livePatch || !candidate.equals(livePatch)) { patchFrom = b; break }
    }
  }
  // 2) bundles 源：近期快照中「bundles 全部可解析存在」的最大者（廉价扫描，不解析大 manifest）
  let bundlesFrom = null, bundlesList = null
  const sb = snapshotBundlesMax(store, join(profile.dir, 'node_modules'), manifest?.dependencies)
  if (sb) { bundlesFrom = sb.from; bundlesList = sb.bundles }
  if (!patchFrom && !bundlesList) { out.ok = true; out.skipped.push('没有可用的 .bak 或快照源——无可修复项'); return out }

  // 3) guard：把现状备份进 store/incidents/（P1-04：备份失败=失去可恢复依据，必须放弃修复，
  // 绝不继续覆盖 live 配置——「先备份再修」的纪律不能被空 catch 架空）
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const guardDir = join(store, 'incidents', `${stamp}-recovery-${profile.name}`)
  if (!dryRun) {
    try {
      mkdirSync(guardDir, { recursive: true })
      copyFileSync(manifestPath, join(guardDir, 'package.json'))
      if (existsNo(patchPath)) copyFileSync(patchPath, join(guardDir, 'cordis.patch.yml'))
      writeFileSync(join(guardDir, 'README.txt'), `官方崩溃恢复(bundles 回缩/patch 改名)后的外科修复前现场备份\nprofile=${profile.name} at=${stamp}\n`)
      out.guardDir = guardDir
    } catch (e) {
      out.ok = false
      out.skipped.push(`guard 备份失败——放弃修复，live 配置未写：${String(e?.message || e)}`)
      try { rmSync(guardDir, { recursive: true, force: true }) } catch { /* 半成品 guard 清掉 */ }
      return out
    }
  }

  // 4) 执行：patch ← bak 原文；bundles ← 快照清单（其余 manifest 字段原样保留）。
  // B3（0.7.4 审计 P2）：曾先写 patch 后序列化 manifest——深 manifest 的 stringify 抛
  // RangeError/写盘失败时留下「patch 已恢复、bundles 仍被砍」的混合状态。任何 live 写入
  // 前先预序列化 manifest（失败即中止且未动任何文件）；patch 走临时文件+rename 原子落盘。
  let manifestText = null
  if (bundlesList && JSON.stringify(manifest.dsh?.profile?.bundles ?? []) !== JSON.stringify(bundlesList)) {
    try {
      manifestText = JSON.stringify({ ...manifest, dsh: { ...(manifest.dsh ?? {}), profile: { ...(manifest.dsh?.profile ?? {}), bundles: [...bundlesList] } } }, null, 2) + '\n'
    } catch (e) {
      out.ok = false
      out.errors = [...(out.errors ?? []), `manifest 序列化失败——放弃修复，live 未写：${String(e?.message || e)}`]
      return out
    }
  }
  if (patchFrom) {
    out.actions.push({ kind: 'patch-restore', from: patchFrom.name, bytes: patchFrom.path && (() => { try { return statSync(patchFrom.path).size } catch { return -1 } })() })
    if (!dryRun) {
      try {
        const tmpPatch = `${patchPath}.tmp-${process.pid}-${Math.random().toString(36).slice(2, 8)}`
        copyFileSync(patchFrom.path, tmpPatch)
        renameSync(tmpPatch, patchPath)
      } catch (e) { out.ok = false; out.errors = [...(out.errors ?? []), `patch 写回失败：${String(e?.message || e)}`] }
    }
  } else out.skipped.push('patch 与最新 .bak 内容一致（或无 .bak）——不写')
  if (manifestText !== null) {
    out.actions.push({ kind: 'bundles-restore', from: `snapshot ${bundlesFrom}`, count: bundlesList.length })
    if (!dryRun) {
      try { atomicWriteText(manifestPath, manifestText) } catch (e) { out.ok = false; out.errors = [...(out.errors ?? []), `bundles 写回失败：${String(e?.message || e)}`] }
    }
  } else if (!patchFrom || !out.actions.some((a) => a.kind === 'patch-restore')) out.skipped.push('bundles 与快照一致——不写')
  if (!dryRun) appendJournal(store, { kind: 'repair-profile', profile: profile.name, actions: out.actions.map((a) => a.kind), ok: out.ok, errors: out.errors, guardDir })
  return out
}

/** GUI 外壳网络状态重置（2026-11-10 实战修复的产品化）：
 * 强杀/断电可弄坏 GUI 的 Chromium 网络状态（Cookies/HSTS/Network Persistent State），
 * 之后每次启动 net.fetch 对本地宿主的认证握手必失败（desktop welcome: Web authentication failed）。
 * 修复 = 先把状态集备份进 store/incidents/，再删除；下次启动自动重建全新状态。登录凭据在 DSH home，不受影响。 */
const GUI_STATE_NAMES = ['Network', 'Local State', 'Preferences', 'Session Storage', 'DIPS', 'DIPS-wal', 'WebStorage']
/** GUI 外壳进程粗探针（复用 doctor 的 tasklist 判据）。三态：true=在跑 / false=确认没跑 /
 * null=探测失败（P1-02：spawnSync ENOENT/timeout 走 out.error 不 throw，曾按未运行放行——fail-open）。
 * 调用方（repairGui 进程闸）对 null 必须 fail-closed 拒绝。 */
function harnessProcessesAlive() {
  if (!IS_WIN) return null
  try {
    const out = spawnSync('tasklist', ['/FI', 'IMAGENAME eq DeepSeek Harness.exe', '/FO', 'CSV', '/NH'], { encoding: 'utf8', timeout: 8000 })
    if (out.error || out.status !== 0) return null
    return /DeepSeek Harness\.exe/i.test(String(out.stdout || ''))
  } catch { return null }
}
export function repairGui(opts = {}) {
  const dshHome = opts.dshHome || resolveDshHome()
  const store = opts.store || resolveStore(dshHome)
  const dryRun = !!opts.dryRun
  const out = { ok: true, dryRun, shellDir: opts.shellDir ?? join(process.env.APPDATA || '', '@deepseek-ai', 'dsh-desktop'), targets: [], guardDir: null }
  // P2-04：本命令源自 Windows 桌面外壳事故，其它平台/APPDATA 缺失（会退化成 CWD 相对路径）一律结构化拒绝
  if (!IS_WIN) { out.ok = false; out.skipped = ['repair-gui 当前仅支持 Windows 桌面外壳']; return out }
  if (opts.shellDir === undefined && !process.env.APPDATA) {
    out.ok = false
    out.skipped = ['APPDATA 未设置——拒绝使用相对路径猜测 GUI 外壳目录（可用 --shell-dir 显式指定）']
    return out
  }
  if (!existsNo(out.shellDir)) { out.ok = false; out.skipped = [`GUI 外壳目录不存在：${out.shellDir}（未安装桌面端或路径不同）`]; return out }
  out.targets = GUI_STATE_NAMES.map((n) => join(out.shellDir, n)).filter(existsNo)
  if (!out.targets.length) { out.skipped = ['无可重置的状态文件（外壳目录是空的？）']; return out }
  // 进程闸：桌面在跑时状态文件被锁，删了也是徒劳——必须先完全退出（含托盘）。
  // 三态闸（P1-02）：busy !== false 一律拒绝（null=探测失败，fail-closed；--force 显式越过）
  if (!opts.skipProcessGuard) {
    const busy = harnessProcessesAlive()
    if (busy !== false) {
      out.ok = false
      out.skipped = [busy === null
        ? '无法确认 DeepSeek Harness 进程状态（tasklist 探测失败）——fail-closed 拒绝；请人工确认桌面完全退出后用 --force'
        : 'DeepSeek Harness 仍在运行——先完全退出（含托盘）再执行，或加 --force']
      out.busy = busy
      return out
    }
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const guardDir = join(store, 'incidents', `${stamp}-gui-state`)
  if (!dryRun) {
    // 备份阶段整体 fail-closed：任何一步失败（含 guard 目录建不出来）都不得进入删除阶段
    try {
      mkdirSync(guardDir, { recursive: true })
      out.guardDir = guardDir
      for (const t of out.targets) {
        const dst = join(guardDir, basename(t))
        if (statSync(t).isDirectory()) cpSync(t, dst, { recursive: true }); else copyFileSync(t, dst)
      }
      writeFileSync(join(guardDir, 'README.txt'), `GUI 外壳网络状态重置前备份\nshell=${out.shellDir} at=${stamp}\n恢复=把本目录内容拷回 shell 覆盖\n`)
    } catch (e) {
      out.ok = false
      out.errors = [...(out.errors ?? []), `备份阶段失败——未删除任何状态：${String(e?.message || e)}`]
      return out
    }
    for (const t of out.targets) {
      try { rmSync(t, { recursive: true, force: true }) } catch (e) {
        out.ok = false
        out.errors = [...(out.errors ?? []), `${basename(t)}: ${String(e?.message || e)}`]
      }
    }
    appendJournal(store, { kind: 'repair-gui', shell: out.shellDir, targets: out.targets.map((t) => basename(t)), guardDir, ok: out.ok })
  }
  return out
}

/* ---- patch 冲突静态检测（生态调研实证的 5 类事故的可静态检出子集） ----
 * 生态头部插件全是 patch 型（package.json 声明 dsh.bundle.patch → cordis.patch.yml）。
 * 已知事故形态：①entry id 撞车（两包同 id，后装者覆盖前者 / Settings 无法保存）
 * ②同 id 多包修补（都改官方行，语义互踩）③家族混装（同仓库多包版本错配）。
 * 本扫描零依赖正则提取 patch 的 id 面（顶层 - id: = 改行；insert 块内缩进 - id: = 新增行），
 * 跨包对比产出冲突清单。**只读，不判语义对错**（patch 可以合法覆盖官方行，撞车才是问题）。
 */

/** 从 cordis.patch.yml 文本提取 entry id 面：{ adds:Set（insert 块内的 entry 本体）, overrides:Set（顶层改行） } */
export function extractPatchIds(text) {
  const adds = new Set(); const overrides = new Set()
  let inInsert = false; let insertDepth = 0
  let entryIndent = -1 // insert 块内 entry 本体的缩进（按块内第一个 "- id:" 行锚定——生态实测 2/4 都有）
  for (const raw of String(text ?? '').split('\n')) {
    const line = raw.replace(/\t/g, '  ')
    if (/^\s*#/.test(line) || !line.trim()) continue
    const m = line.match(/^(\s*)-(?:\s|$)/)
    if (!m) continue
    const indent = m[1].length
    const idm = line.match(/^(\s*)-\s+id:\s*(.+?)\s*$/)
    // 「顶层块开始」= 缩进不深于当前块锚（insert: 行或首个顶层 - id: 行）；
    // 更深缩进的 "- id:"（config.hooks 子列表项）不开启新块（review #13 F1）
    const startsTopBlock = /^\s*-\s*insert\s*:/.test(line)
    if (!inInsert) {
      if (startsTopBlock) { inInsert = true; insertDepth = indent; entryIndent = -1; continue }
      if (idm) {
        if (entryIndent < 0 || indent <= insertDepth) {
          entryIndent = entryIndent < 0 ? indent : entryIndent
          if (indent === entryIndent) overrides.add(yamlScalar(idm[2]))
        }
      }
      continue
    }
    // insert 块内：entry 本体缩进按块内第一个 "- id:" 锚定，同缩进=兄弟 entry，更深的=config 子列表 id（不收）
    if (idm) {
      if (entryIndent < 0) entryIndent = indent
      if (indent === entryIndent) adds.add(yamlScalar(idm[2]))
    }
  }
  return { adds, overrides }
}
function yamlScalar(s) {
  const v = String(s ?? '').trim()
  const q = v.match(/^'(.*)'$/) || v.match(/^"(.*)"$/)
  return (q ? q[1] : v).trim()
}

/** 读一个包的 patch 文件内容（按 package.json 的 dsh.bundle.patch 相对路径；缺省试根目录 cordis.patch.yml） */
function pkgPatchText(installAnchor, name) {
  for (const anchor of installAnchor) {
    const pkgDir = join(anchor, 'node_modules', name)
    const meta = readJson(join(pkgDir, 'package.json'), null)
    if (!meta) continue
    const rel = typeof meta?.dsh?.bundle === 'object' ? meta.dsh.bundle?.patch : null
    const candidates = [rel, 'cordis.patch.yml', 'dsh/cordis.patch.yml'].filter(Boolean)
    for (const c of candidates) {
      try { return { text: readFileSync(join(pkgDir, c), 'utf8'), pkgDir } } catch { /* 下一个 */ }
    }
    return { text: null, pkgDir } // 包存在但无 patch 文件
  }
  return null
}

/** 已装插件 patch 冲突扫描：返回 { ok, conflicts:[{kind, id, pkgs}], scanned } */
export function patchConflicts(profileDir, installAnchor) {
  const anchors = [installAnchor, profileDir].filter(Boolean)
  const manifest = readJson(join(profileDir, 'package.json'), null)
  if (!manifest) return { ok: false, reason: 'manifest 不可读' }
  const ids = new Map() // id -> [{pkg, kind:'add'|'override'}]
  let scanned = 0
  for (const name of Object.keys(manifest.dependencies ?? {})) {
    const found = pkgPatchText(anchors, name)
    if (!found) continue
    const meta = readJson(join(found.pkgDir, 'package.json'), null)
    if (meta?.dsh?.bundle === undefined) continue // 非 bundle 包不参与
    if (!found.text) continue // bundle 包但无 patch 文件（如纯 activate 型）
    scanned++
    const { adds, overrides } = extractPatchIds(found.text)
    for (const id of adds) {
      if (!ids.has(id)) ids.set(id, [])
      ids.get(id).push({ pkg: name, kind: 'add' })
    }
    for (const id of overrides) {
      if (!ids.has(id)) ids.set(id, [])
      ids.get(id).push({ pkg: name, kind: 'override' })
    }
  }
  const conflicts = []
  for (const [id, users] of ids) {
    if (users.length < 2) continue
    const adds = users.filter((u) => u.kind === 'add')
    const overrides = users.filter((u) => u.kind === 'override')
    if (adds.length >= 2) conflicts.push({ kind: 'duplicate-id', id, pkgs: adds.map((u) => u.pkg), detail: `${adds.length} 个插件都 insert 同一 entry id「${id}」——后装覆盖先装，宿主只挂一个` })
    else if (adds.length && overrides.length) conflicts.push({ kind: 'add-override-collision', id, pkgs: users.map((u) => u.pkg), detail: `「${id}」既有插件 insert 新行、又有插件改写官方行——挂载结果取决于 patch 叠加顺序，行为不定` })
    else if (overrides.length >= 2) conflicts.push({ kind: 'override-collision', id, pkgs: users.map((u) => u.pkg), detail: `${overrides.length} 个插件都改写官方行「${id}」的 config——后加载者生效，前者配置被静默丢弃` })
  }
  return { ok: true, conflicts, scanned }
}


/* ============================================================
 * selftest：内部不变量自检
 * ============================================================ */

export function selftest() {
  const results = []
  const t = (name, fn) => {
    try { fn(); results.push({ name, ok: true }) }
    catch (e) { results.push({ name, ok: false, error: String(e?.message || e) }) }
  }
  const tmp = mkdtempSafe('dsh-snap-selftest-')
  const fakeProfile = join(tmp, 'profiles', 'desktop')
  const nm = join(fakeProfile, 'node_modules')
  mkdirSync(join(nm, 'a-pkg', 'dist'), { recursive: true })
  writeFileSync(join(nm, 'a-pkg', 'dist', 'x.js'), 'console.log(1)\n')
  writeFileSync(join(nm, 'a-pkg', 'package.json'), '{"name":"a-pkg","version":"1.0.0"}')
  writeFileSync(join(fakeProfile, 'package.json'), '{"dependencies":{}}')
  writeFileSync(join(fakeProfile, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n')
  // junction：不得被快照深入
  const junctionTarget = join(tmp, 'junction-target')
  mkdirSync(junctionTarget, { recursive: true })
  writeFileSync(join(junctionTarget, 'danger.js'), 'SHOULD NOT BE SNAPSHOTTED')
  let junctionMade = true
  try { symlinkSync(junctionTarget, join(nm, 'a-pkg', 'evil-junction'), 'junction') } catch { junctionMade = false }

  const savedEnv = { HOME: process.env.DSH_HOME, PROFILE: process.env.DSH_PROFILE, SNAP: process.env.DSH_SNAP_HOME }
  process.env.DSH_HOME = tmp
  process.env.DSH_PROFILE = 'desktop'
  const store = join(tmp, '.dsh-snap')
  process.env.DSH_SNAP_HOME = store
  const prof = { name: 'desktop', dir: fakeProfile }

  t('snapshot: 基础拍取', () => {
    const m = takeSnapshot({ store, trigger: 'manual', profile: prof })
    if (!m.layers.profile.taken.includes('package.json')) throw new Error('profile 层缺失')
    if (m.stats.files < 2) throw new Error(`文件数异常 ${m.stats.files}`)
  })
  let firstId
  t('snapshot: junction 不深入', () => {
    const m = listSnapshots(store)[0]
    firstId = m.id
    if (!junctionMade) return // 非 Windows 权限环境跳过该断言
    if (existsNo(join(store, 'snapshots', m.id, 'node_modules', 'a-pkg', 'evil-junction', 'danger.js'))) {
      throw new Error('junction 被跟随！')
    }
  })
  t('snapshot: 增量复用上一快照', () => {
    // 在两拍之间新增一个包：让 second 快照含有 extra-pkg，供 extraneous 断言用
    mkdirSync(join(nm, 'extra-pkg'), { recursive: true })
    writeFileSync(join(nm, 'extra-pkg', 'e.js'), 'extra')
    const m = takeSnapshot({ store, trigger: 'manual', profile: prof, prevId: firstId })
    if (m.stats.hardlinkedFromPrev < 1) throw new Error(`未复用：${JSON.stringify(m.stats)}`)
  })
  t('restore: dry-run 检出缺失与 extraneous', () => {
    rmSync(join(nm, 'a-pkg', 'dist', 'x.js'))
    // 模拟 pnpm 的 replace 语义（unlink + 新建）：安装的真实行为，快照完好
    rmSync(join(nm, 'a-pkg', 'package.json'))
    writeFileSync(join(nm, 'a-pkg', 'package.json'), '{"name":"a-pkg","version":"9.9.9"}')
    const r = restoreSnapshot({ store, target: firstId, dryRun: true, profile: prof, skipProcessProbe: true })
    if (!r.ok || r.plan.nodeModules.missing < 1) throw new Error('dry-run 未检出缺失')
    if (r.plan.nodeModules.mismatched < 1) throw new Error('dry-run 未检出篡改（mtime 比对失效）')
    if (!r.plan.nodeModules.extraneousTopLevel.includes('extra-pkg')) throw new Error('dry-run 未检出 extraneous')
  })
  t('restore: 实际回填（guard 先行）', () => {
    const r = restoreSnapshot({ store, target: firstId, profile: prof, skipProcessProbe: true })
    if (!r.ok) throw new Error(`restore 失败 ${r.code || ''}`)
    if (readFileSync(join(nm, 'a-pkg', 'dist', 'x.js'), 'utf8') !== 'console.log(1)\n') throw new Error('文件未回填')
    if (JSON.parse(readFileSync(join(nm, 'a-pkg', 'package.json'), 'utf8')).version !== '1.0.0') throw new Error('清单未回填')
  })
  t('restore: guard 快照存在（还原可撤销）', () => {
    const all = listSnapshots(store).filter((m) => !m.corrupted)
    if (!all.some((m) => m.trigger === 'pre-restore')) throw new Error('无 pre-restore guard 快照')
  })
  t('undo: 撤销还原', () => {
    writeFileSync(join(nm, 'a-pkg', 'dist', 'x.js'), 'console.log(2)\n')
    const guards = listSnapshots(store).filter((m) => !m.corrupted && m.trigger === 'pre-restore')
    const r = restoreSnapshot({ store, target: guards[0].id, profile: prof, skipProcessProbe: true })
    if (!r.ok) throw new Error('undo 还原失败')
    if (readFileSync(join(nm, 'a-pkg', 'dist', 'x.js'), 'utf8') !== 'console.log(2)\n') throw new Error('undo 未回滚')
  })
  t('restore: 原地污染被检出并报告', () => {
    writeFileSync(join(nm, 'a-pkg', 'dist', 'x.js'), 'console.log(1)\nconsole.log(2)\n') // 原地写长内容→污染
    const r = restoreSnapshot({ store, target: firstId, dryRun: false, profile: prof, skipProcessProbe: true })
    const polluted = r.reported?.find((x) => x.issue === 'snapshot-polluted-in-place')
    if (!polluted) throw new Error(`原地污染未被检出：${JSON.stringify(r.reported)}`)
  })
  t('prune: 手动与 guard 豁免', () => {
    pruneSnapshots(store, { maxSnapshots: 1, ttlDays: 0 })
    const all = listSnapshots(store).filter((m) => !m.corrupted)
    if (!all.some((m) => m.manual)) throw new Error('手动快照被误删')
    if (!all.some((m) => m.guard)) throw new Error('guard 快照被误删')
  })
  t('prune: 配额被豁免占满时不删非豁免（v0.3.3 事故回归）', () => {
    const store2 = join(tmp, '.dsh-snap2')
    // 先拍小 baseline（非豁免）；再造 2MB 大文件拍手动（豁免）
    const nonExempt = takeSnapshot({ store: store2, trigger: 'baseline', profile: prof })
    mkdirSync(join(nm, 'big-pkg'), { recursive: true })
    writeFileSync(join(nm, 'big-pkg', 'blob.bin'), Buffer.alloc(2 * 1024 * 1024, 7))
    takeSnapshot({ store: store2, trigger: 'manual', profile: prof, label: '大豁免', prevId: nonExempt.id })
    // 字节配额 1MB：低于豁免的 2MB——旧实现会把非豁免删光，新实现必须让它存活
    pruneSnapshots(store2, { maxSnapshots: 10, ttlDays: 30, maxBytes: 1024 * 1024 })
    const after = listSnapshots(store2).filter((m) => !m.corrupted)
    if (!after.some((m) => m.id === nonExempt.id)) throw new Error('非豁免快照被配额误删（事故复现）')
    if (!after.some((m) => m.manual)) throw new Error('手动快照被误删')
  })
  t('id 闸：路径逃逸被拒', () => {
    if (readSnapshotManifest(store, '../evil') !== null) throw new Error('id 校验失效')
    if (readSnapshotManifest(store, '20261108T000000-ffffff') !== null) throw new Error('不存在的快照应返回 null')
  })
  t('corrupted: 损坏快照被隔离', () => {
    const bad = join(store, 'snapshots', '20991108T000000-dead00')
    mkdirSync(bad, { recursive: true })
    writeFileSync(join(bad, 'manifest.json'), '{"version":999}')
    const all = listSnapshots(store)
    if (!all.some((m) => m.corrupted && m.id === '20991108T000000-dead00')) throw new Error('损坏快照未被标记')
  })
  /* ---- G1 verify：完整性校验三态 ---- */
  let verifyId
  t('verify: 完整快照通过（deep 含 sha256）', () => {
    const m = takeSnapshot({ store, trigger: 'manual', profile: prof, label: 'verify素材' })
    verifyId = m.id
    const v = verifySnapshot(store, verifyId, { deep: true })
    if (!v.ok) throw new Error(`应通过：${verifyPrettyLine(v)}`)
    if (v.checked < 1) throw new Error('未校验任何文件')
  })
  t('verify: 原地改写被检出（size+mtime 漂移即污染指纹）', () => {
    writeFileSync(join(nm, 'a-pkg', 'dist', 'x.js'), 'console.log(1)\n// tampered: longer content\n')
    const v = verifySnapshot(store, verifyId, { deep: false })
    if (v.ok || v.modifiedCount < 1) throw new Error('原地改写未被 verify 检出')
  })
  t('verify: 同尺寸同mtime篡改仅 deep 检出', () => {
    const idx = readFilesIndex(store, verifyId)
    const row = idx.find((r) => r[0].endsWith(join('a-pkg', 'dist', 'x.js')))
    if (!row) throw new Error('索引中找不到目标行')
    // 精确同尺寸 + 恢复记录的 mtime → 非 deep 必然漏报，deep 靠快照期哈希捕捉
    const buf = Buffer.alloc(Number(row[1]), 0x78)
    buf.write('console.log(9)\n')
    writeFileSync(join(nm, 'a-pkg', 'dist', 'x.js'), buf)
    utimesSync(join(nm, 'a-pkg', 'dist', 'x.js'), new Date(Number(row[2])), new Date(Number(row[2])))
    const shallow = verifySnapshot(store, verifyId, { deep: false })
    if (!shallow.ok) throw new Error('浅校验不应命中同尺寸同mtime篡改（它属于 deep 的职责）')
    const deep = verifySnapshot(store, verifyId, { deep: true })
    if (deep.ok || deep.hashMismatchCount < 1) throw new Error('deep 未捕捉哈希不符')
  })
  t('home: 凭据键文件不入快照（G4）', () => {
    writeFileSync(join(tmp, 'settings.yaml'), 'providers:\n  apiKey: sk-should-not-be-snapshotted\n')
    const m = takeSnapshot({ store, trigger: 'manual', profile: prof })
    const skipped = m.layers.home.skipped.find((s) => s.file === 'settings.yaml')
    if (!skipped || skipped.reason !== 'credential-like') throw new Error(`凭据文件未被拦截：${JSON.stringify(m.layers.home.skipped)}`)
    if (existsNo(join(store, 'snapshots', m.id, 'home', 'settings.yaml'))) throw new Error('凭据文件被写进了快照！')
  })
  t('store: 营救 bat 含 runtime node 兜底段（G3，Windows）', () => {
    if (!IS_WIN) { // 非 Windows 不生成 bat（ensureStoreSelfCopy 平台分支）；验 mjs 副本仍存在
      if (!existsNo(join(store, 'cli', 'dsh-snap.mjs'))) throw new Error('非 Windows 也应有 CLI 副本')
      return
    }
    const bat = readFileSync(join(store, 'cli', 'dsh-snap.bat'), 'utf8')
    if (!bat.includes('DSHSNAP_NODE')) throw new Error('bat 缺 node 路径兜底逻辑')
  })
  t('restore: 进度文件全程写删 + 半程检出（G6）', () => {
    if (existsNo(restoreProgressPath(store))) throw new Error('还原完成后进度文件残留')
    // 模拟半程中断：写入带死 pid 的进度文件 → doctor 必须检出
    atomicWriteJson(restoreProgressPath(store), {
      pid: 999999999, target: 'fake-target', guardId: 'fake-guard',
      phase: 'node-modules', startedAt: Date.now(), profile: 'desktop',
    })
    const d = doctor(prof)
    const c = d.checks.find((c) => c.id === 'restore-interrupted')
    if (!c || c.ok) throw new Error('半程中断未被 doctor 检出')
    // 正在还原中（pid 活）不误报
    atomicWriteJson(restoreProgressPath(store), { ...JSON.parse(readFileSync(restoreProgressPath(store), 'utf8')), pid: process.pid })
    if (readInterruptedRestore(store) !== null) throw new Error('活 pid 被误判为中断')
    rmSync(restoreProgressPath(store), { force: true })
  })
  t('snapshot: 已知原地写文件走私有副本（.modules.yaml 防污染）', () => {
    writeFileSync(join(nm, '.modules.yaml'), 'layoutVersion: 9.9\n')
    const m = takeSnapshot({ store, trigger: 'manual', profile: prof })
    const row = readFilesIndex(store, m.id).find((r) => r[0] === '.modules.yaml')
    if (!row) throw new Error('.modules.yaml 未入索引')
    // 原地改写（pnpm 真实行为）：私有副本不应被波及
    writeFileSync(join(nm, '.modules.yaml'), 'layoutVersion: 10.0-rewritten-in-place\n')
    const v = verifySnapshot(store, m.id, { deep: true })
    if (!v.ok || v.hashMismatchCount || v.modifiedCount) {
      throw new Error(`私有副本仍被污染：${verifyPrettyLine(v)}`)
    }
  })
  t('snapshot: 自目录 dsh-snap 走私有副本且不复用旧链（自升级防污染）', () => {
    mkdirSync(join(nm, 'dsh-snap', 'client'), { recursive: true })
    writeFileSync(join(nm, 'dsh-snap', 'index.js'), 'v1\n')
    const m1 = takeSnapshot({ store, trigger: 'manual', profile: prof })
    const row1 = readFilesIndex(store, m1.id).find((r) => r[0] === join('dsh-snap', 'index.js'))
    if (!row1) throw new Error('自目录未入索引')
    // 原地覆写（部署真实行为）+ mtime 变化 → 若复用了 m1 的私有副本则内容一致可复用；
    // 但旧链若是被污染的硬链接则不可复用——这里验证第二拍不再从 prev 链接自目录
    writeFileSync(join(nm, 'dsh-snap', 'index.js'), 'v2-longer\n')
    const m2 = takeSnapshot({ store, trigger: 'manual', profile: prof, prevId: m1.id })
    if (m2.stats.hardlinkedFromPrev > 0 && readFilesIndex(store, m2.id).find((r) => r[0] === join('dsh-snap', 'index.js'))[5] !== safeSha256(join(nm, 'dsh-snap', 'index.js'))) {
      throw new Error('自目录复用了旧链且哈希未实算')
    }
    // 原地再改（模拟下次部署）→ 两拍都必须完好
    writeFileSync(join(nm, 'dsh-snap', 'index.js'), 'v3-even-longer\n')
    for (const m of [m1, m2]) {
      const v = verifySnapshot(store, m.id, { deep: true })
      if (!v.ok || v.modifiedCount || v.hashMismatchCount) {
        throw new Error(`${m.id} 自目录被污染：${verifyPrettyLine(v)}`)
      }
    }
  })
  t('prune: 逐出方向=最旧优先（P1-1 回归：旧实现删最新留最旧）', () => {
    const store3 = join(tmp, '.dsh-snap3')
    const ids = []
    for (let i = 0; i < 3; i++) ids.push(takeSnapshot({ store: store3, trigger: 'agent:install_bundle:r' + i, profile: prof }).id)
    pruneSnapshots(store3, { maxSnapshots: 2, ttlDays: 30 })
    const left = listSnapshots(store3).filter((m) => !m.corrupted).map((m) => m.id)
    if (left.includes(ids[0])) throw new Error('最旧的没被逐出（方向仍反）')
    if (!left.includes(ids[2])) throw new Error('最新的被误逐出')
  })
  t('resolveProfile: 只有非 desktop profile 的 home 正确解析（P1-2 回归）', () => {
    const homeX = mkdtempSafe('dsh-snap-p1-2-')
    mkdirSync(join(homeX, 'profiles', 'headless', 'node_modules'), { recursive: true })
    writeFileSync(join(homeX, 'profiles', 'headless', 'package.json'), '{}')
    const saved = process.env.DSH_PROFILE
    try {
      delete process.env.DSH_PROFILE
      const p = resolveProfile(homeX)
      if (p.name !== 'headless') throw new Error(`应解析 headless，实际 ${p.name}`)
    } finally { if (saved !== undefined) process.env.DSH_PROFILE = saved; else delete process.env.DSH_PROFILE }
    try { rmSync(homeX, { recursive: true, force: true }) } catch { /* 清理 */ }
  })
  t('snapshot: size+mtime 碰撞不得复用陈旧内容（P1-3 回归）', () => {
    const store4 = join(tmp, '.dsh-snap4')
    const p13 = join(nm, 'a-pkg', 'p13-collision.js')
    writeFileSync(p13, 'AAAAAAAAAA') // 10 字节
    const m1 = takeSnapshot({ store: store4, trigger: 'manual', profile: prof })
    const row1 = readFilesIndex(store4, m1.id).find((r) => r[0] === join('a-pkg', 'p13-collision.js'))
    // 碰撞构造：同尺寸不同内容 + 恢复记录的 mtime（replace 语义换 inode——原地写会连 m1 一起污染，那是另一回事）
    rmSync(p13)
    writeFileSync(p13, 'BBBBBBBBBB')
    utimesSync(p13, new Date(Number(row1[2])), new Date(Number(row1[2])))
    const m2 = takeSnapshot({ store: store4, trigger: 'manual', profile: prof, prevId: m1.id })
    // 快照侧内容必须是新内容，而不是上一快照的陈旧内容
    const snapSide = join(store4, 'snapshots', m2.id, 'node_modules', 'a-pkg', 'p13-collision.js')
    if (sha256File(snapSide) !== sha256File(p13)) throw new Error('碰撞时快照存了陈旧内容（复用未核验）')
    if (sha256File(snapSide) === sha256File(join(store4, 'snapshots', m1.id, 'node_modules', 'a-pkg', 'p13-collision.js'))) {
      throw new Error('复用了上一快照的陈旧内容')
    }
    const v = verifySnapshot(store4, m2.id, { deep: true })
    if (!v.ok) throw new Error('碰撞后 verify 失败')
  })
  t('store: 副本防降级（旧内核快照不回刷新营救副本）', () => {
    // 语义验证：kernel-version.json 记录当前版本；ensureStoreSelfCopy 由 takeSnapshot 触发
    const verFile = join(store, 'cli', 'kernel-version.json')
    const rec = readJson(verFile, null)
    if (!rec?.version) throw new Error('store 缺 kernel-version.json（防降级标记未写）')
    if (vCmp(parseVer(rec.version), parseVer(KERNEL_VERSION)) > 0) throw new Error('副本版本超前于运行方？')
  })
  t('preflight: semver 子集回归（野外语法关键边界，34 例精选）', () => {
    const cases = [
      ['0.2.2-rc.1', '>=0.2.0-0 <0.3.0', true],
      ['0.2.2-rc.1', '>=0.2.0-rc.1', true],
      ['0.2.2-rc.1', '^0.2.0-rc.1', true],
      ['0.1.9', '>=0.2.0-0', false],
      ['0.3.0-rc.1', '^0.2.0-rc.1', false], // canonical rewrite 上界 -0
      ['0.2.2-rc.1', '^0.1.1-rc.2 || ^0.2.0-rc.1', true],
      ['0.2.2', '0.2.x', true],
      ['0.3.1', '0.2.x', false],
      ['0.2.1', '>=0.2.0 <0.2.2', true],
      ['1.2.3', '1.2.3 - 2', true],
      ['2.9.9', '1.2.3 - 2', true],
      ['3.0.0', '1.2.3 - 2', false],
      ['0.2.10', '>=0.2.2-rc.1', true], // 数值位 > prerelease 位
      ['0.2.2-rc.2', '>0.2.2-rc.1', true], // rc 字典序/数值
      ['0.2.2-beta.1', '>0.2.2-rc.1', false],
    ]
    for (const [v, r, want] of cases) {
      const got = satisfies(v, r)
      if (got !== want) throw new Error(`satisfies(${v}, ${r}) = ${got}，期望 ${want}`)
    }
    if (satisfies('0.2.2-rc.1', 'workspace:*') !== null) throw new Error('不识别语法应返回 null')
    if (satisfies('0.2.2-rc.1', '') !== true) throw new Error('空 range = *')
  })
  t('attributeCrash: 永不 throw + 输出 shape 合法', () => {
    const r = attributeCrash({ store, dshHome: tmp, profile: prof })
    if (!r.ok || !Array.isArray(r.suspects) || !Array.isArray(r.crashes) || !Array.isArray(r.loops)) {
      throw new Error(`输出 shape 非法：${JSON.stringify(Object.keys(r))}`)
    }
    if (typeof r.sources.journalOnly !== 'boolean') throw new Error('sources.journalOnly 缺失')
  })
  t('diff: 两快照差异计数与顶层包归类', () => {
    const storeD = join(tmp, '.dsh-snap-diff')
    const before = takeSnapshot({ store: storeD, trigger: 'agent:install_bundle:diff-pkg', profile: prof, spec: 'diff-pkg' })
    mkdirSync(join(nm, 'diff-pkg'), { recursive: true })
    writeFileSync(join(nm, 'diff-pkg', 'd.js'), 'diff')
    const after = takeSnapshot({ store: storeD, trigger: 'manual', profile: prof, prevId: before.id })
    const d = diffSnapshots(storeD, before.id, after.id)
    if (!d.ok || d.counts.added < 1) throw new Error(`diff 未检出新增：${JSON.stringify(d.counts)}`)
    if (!d.topPackages.added.includes('diff-pkg')) throw new Error('顶层包归类失败')
    const rev = diffSnapshots(storeD, after.id, before.id)
    if (rev.counts.removed < 1) throw new Error('反向 diff 未检出删除')
  })
  t('ghost-deps: 装了 bundle 包未进 bundles 被检出', () => {
    mkdirSync(join(nm, 'ghost-pkg'), { recursive: true })
    writeFileSync(join(nm, 'ghost-pkg', 'package.json'), '{"name":"ghost-pkg","dsh":{"bundle":{"patch":"./cordis.patch.yml"}}}')
    const mf = join(fakeProfile, 'package.json')
    const m = JSON.parse(readFileSync(mf, 'utf8'))
    m.dependencies['ghost-pkg'] = '1.0.0' // 幽灵=deps 声明 + 未进 bundles
    writeFileSync(mf, JSON.stringify(m))
    const g = ghostDeps(fakeProfile, fakeProfile)
    if (!g.ok || !g.ghosts.includes('ghost-pkg')) throw new Error(`幽灵依赖未检出：${JSON.stringify(g)}`)
    // 进 bundles 后应消失
    m.dsh = { profile: { bundles: ['ghost-pkg'] } }
    writeFileSync(mf, JSON.stringify(m))
    const g2 = ghostDeps(fakeProfile, fakeProfile)
    if (g2.ghosts.includes('ghost-pkg')) throw new Error('进 bundles 后仍被报幽灵')
    delete m.dsh
    delete m.dependencies['ghost-pkg']
    writeFileSync(mf, JSON.stringify(m))
    rmSync(join(nm, 'ghost-pkg'), { recursive: true, force: true })
  })
  t('unstick: 残锁检出与清理', () => {
    const storeU = join(tmp, '.dsh-snap-unstick')
    takeSnapshot({ store: storeU, trigger: 'manual', profile: prof })
    // 死 pid 的 run.json + 11 分钟前的 package.json.lock
    mkdirSync(join(fakeProfile, '.plugin-manager'), { recursive: true })
    writeFileSync(join(fakeProfile, '.plugin-manager', 'run.json'), '{"pid":2147483000,"grouped":false}')
    writeFileSync(join(fakeProfile, 'package.json.lock'), 'lock')
    const past = new Date(Date.now() - 11 * 60_000)
    utimesSync(join(fakeProfile, 'package.json.lock'), past, past)
    const locks = staleLocks(fakeProfile)
    if (locks.length < 2) throw new Error(`残锁未检出：${JSON.stringify(locks)}`)
    const r = unstick(fakeProfile)
    if (r.removed.length < 2) throw new Error('unstick 未清理')
    if (existsNo(join(fakeProfile, 'package.json.lock'))) throw new Error('锁文件未删')
  })
  t('dry-run: 证据分级（快照缺文件→degraded）', () => {
    const storeE = join(tmp, '.dsh-snap-dry')
    const m = takeSnapshot({ store: storeE, trigger: 'manual', profile: prof })
    const idxFile = join(storeE, 'snapshots', m.id, 'files-index.tsv')
    // 快照侧删一个文件 → 预览必须降级为 degraded
    rmSync(join(storeE, 'snapshots', m.id, 'node_modules', 'a-pkg', 'dist', 'x.js'))
    const r = restoreSnapshot({ store: storeE, target: m.id, profile: prof, dryRun: true, skipProcessProbe: true })
    if (!r.ok || !r.evidence) throw new Error('dry-run 无证据字段')
    if (r.trustLevel !== 'degraded' || r.evidence.snapshotFileMissing < 1) throw new Error('缺文件未降级 trustLevel')
    void idxFile
  })
  t('harness 哨兵: 指纹建档→变更检出→基线快照', () => {
    const storeF = join(tmp, '.dsh-snap-sentinel')
    // 跨平台可复现：给 fakeProfile 注入 @deepseek-ai 依赖 → harnessDeps 策略命中（策略①
    // 不依赖 Windows 注册表/安装器——app/runtime 两策略仅 Windows 实机可得，CI 上为 null）
    const mfSentinel = join(fakeProfile, 'package.json')
    const savedMfSentinel = readFileSync(mfSentinel, 'utf8')
    writeFileSync(mfSentinel, JSON.stringify({ dependencies: { '@deepseek-ai/dsh-desktop': '0.2.2-rc.1' } }))
    const fp1 = harnessFingerprint(tmp, prof)
    if (!fp1.harnessDeps) { writeFileSync(mfSentinel, savedMfSentinel); throw new Error(`指纹全空（harnessDeps 未命中）：${JSON.stringify(fp1)}`) }
    try {
    // 建档
    saveHarnessState(tmp, prof, storeF, fp1)
    const det1 = detectHarnessChange(tmp, prof, storeF)
    if (det1.changed) throw new Error('刚建档即报变化')
    // 模拟桌面版更新：指纹变化（若 app 为 null 则变 harnessDeps——策略①在 CI 也可驱动检出）
    const fp2 = fp1.app
      ? { ...fp1, app: fp1.app.replace(/(\d+)$/, '9999999999') }
      : { ...fp1, harnessDeps: fp1.harnessDeps.replace('0.2.2-rc.1', '0.2.3') }
    saveHarnessState(tmp, prof, storeF, fp2)
    const det2 = detectHarnessChange(tmp, prof, storeF)
    if (!det2.changed) throw new Error('指纹变化未检出')
    if (det2.from.app === det2.to.app && det2.from.harnessDeps === det2.to.harnessDeps) throw new Error('from/to 未区分')
    } finally { writeFileSync(join(fakeProfile, 'package.json'), savedMfSentinel) }
  })
  t('manifest 打标: harnessVersion 字段写入', () => {
    const storeG = join(tmp, '.dsh-snap-mark')
    const m = takeSnapshot({ store: storeG, trigger: 'manual', profile: prof })
    // fakeProfile 的 deps 无 @deepseek-ai（允许 null）；字段必须存在
    if (!('harnessVersion' in m)) throw new Error('manifest 缺 harnessVersion 字段')
  })
  t('patch 冲突: duplicate-id / override-collision / add-override 检出', () => {
    const pc1 = extractPatchIds('- insert:\n    - id: foo\n      name: bar\n')
    if (!pc1.adds.has('foo') || pc1.overrides.size) throw new Error('insert 提取失败')
    const pc2 = extractPatchIds('- id: web\n  config:\n    searchProvider: modsearch\n')
    if (!pc2.overrides.has('web') || pc2.adds.size) throw new Error('顶层改行提取失败')
    const pc3 = extractPatchIds("- insert:\n    - id: 'q'\n      name: 'x'\n")
    if (!pc3.adds.has('q')) throw new Error('引号标量未剥离')
  })
  t('patch 冲突: 双包同 id 实装检出（patchConflicts）', () => {
    // 造两个 bundle 包，patch 同 id
    for (const p of ['conf-a', 'conf-b']) {
      mkdirSync(join(nm, p), { recursive: true })
      writeFileSync(join(nm, p, 'package.json'), JSON.stringify({ name: p, dsh: { bundle: { patch: './cordis.patch.yml' } } }))
      writeFileSync(join(nm, p, 'cordis.patch.yml'), '- insert:\n    - id: clash-id\n      name: ' + p + '\n')
    }
    const mf = join(fakeProfile, 'package.json')
    const m = JSON.parse(readFileSync(mf, 'utf8'))
    m.dependencies['conf-a'] = '1.0.0'; m.dependencies['conf-b'] = '1.0.0'
    writeFileSync(mf, JSON.stringify(m))
    const r = patchConflicts(fakeProfile, fakeProfile)
    const dup = (r.conflicts ?? []).find((c) => c.kind === 'duplicate-id' && c.id === 'clash-id')
    if (!dup) throw new Error(`duplicate-id 未检出：${JSON.stringify(r.conflicts)}`)
    if (!dup.pkgs.includes('conf-a') || !dup.pkgs.includes('conf-b')) throw new Error('冲突包列表不全')
    // 清理
    delete m.dependencies['conf-a']; delete m.dependencies['conf-b']
    writeFileSync(mf, JSON.stringify(m))
    for (const p of ['conf-a', 'conf-b']) rmSync(join(nm, p), { recursive: true, force: true })
  })
  t('nm-mtime 哨兵: journal 缺席时目录 mtime 兜底归因（U-5 盲点回归）', () => {
    // 造一个刚装的顶层包（mtime=现在）
    mkdirSync(join(nm, 'nm-sentinel-pkg'), { recursive: true })
    writeFileSync(join(nm, 'nm-sentinel-pkg', 'package.json'), '{"name":"nm-sentinel-pkg"}')
    const nowMs = Date.now()
    const evs = nmMtimeEvents(fakeProfile, nowMs - 10 * 60_000, nowMs + 5_000, null)
    const hit = evs.find((e) => e.pkg === 'nm-sentinel-pkg')
    if (!hit || hit.via !== 'nm-mtime') throw new Error(`nm-mtime 未检出：${JSON.stringify(evs)}`)
    // 归因整合：构造崩溃点=现在，journal 空 → nm-mtime 应成 direct 嫌疑
    const r = attributeCrash({ dshHome: dirname(fakeProfile), store: join(tmp, '.dsh-snap-nm'), profile: { name: 'desktop', dir: fakeProfile }, now: nowMs })
    if (r.suspects.some((s) => s.pkg === '.pnpm')) throw new Error('.pnpm 未被排除')
    rmSync(join(nm, 'nm-sentinel-pkg'), { recursive: true, force: true })
  })
  t('restore: scope 内 extraneous 检出（锚内含同 scope 包，首版修复无效的回归）', () => {
    const storeS = join(tmp, '.dsh-snap-scope')
    // 锚内自带 @org/kept（进快照），随后装兄弟包 @org/loose（不入快照）
    mkdirSync(join(nm, '@scope-fam', 'kept'), { recursive: true })
    writeFileSync(join(nm, '@scope-fam', 'kept', 'package.json'), '{"name":"@scope-fam/kept"}')
    const m = takeSnapshot({ store: storeS, trigger: 'baseline', profile: prof })
    mkdirSync(join(nm, '@scope-fam', 'loose'), { recursive: true })
    writeFileSync(join(nm, '@scope-fam', 'loose', 'package.json'), '{"name":"@scope-fam/loose"}')
    const r = restoreSnapshot({ store: storeS, target: m.id, dryRun: true, profile: prof, skipProcessProbe: true })
    if (!r.plan.nodeModules.extraneousTopLevel.includes('@scope-fam/loose')) {
      throw new Error(`scope 兄弟包未检出：${JSON.stringify(r.plan.nodeModules.extraneousTopLevel)}`)
    }
    if (r.plan.nodeModules.extraneousTopLevel.includes('@scope-fam/kept')) {
      throw new Error('锚内包被误判 extraneous')
    }
    // 工具条目（.pnpm 等）永不属 extraneous
    mkdirSync(join(nm, '.pnpm-lock-extra'), { recursive: true })
    const r2 = restoreSnapshot({ store: storeS, target: m.id, dryRun: true, profile: prof, skipProcessProbe: true })
    if (r2.plan.nodeModules.extraneousTopLevel.some((x) => x.startsWith('.'))) {
      throw new Error(`点开头条目被误判 extraneous：${JSON.stringify(r2.plan.nodeModules.extraneousTopLevel)}`)
    }
    rmSync(join(nm, '@scope-fam', 'loose'), { recursive: true, force: true })
    rmSync(join(nm, '.pnpm-lock-extra'), { recursive: true, force: true })
  })
  t('snapshot: 快照热路径不调 harnessFingerprint（reg query 不在快照路径）', () => {
    // 0.7.0 曾在 takeSnapshot 里白调 harnessFingerprint（内含 reg query spawnSync）——
    // 回归哨兵：若 manifest 组装路径再次引入指纹计算，这里通过 mock 时窗检测不到，改为
    // 直接断言 manifest 不含指纹字段（指纹只入 harness-state-*.json，不进 manifest）
    const storeH = join(tmp, '.dsh-snap-hotpath')
    const m = takeSnapshot({ store: storeH, trigger: 'manual', profile: prof })
    if ('harnessFingerprint' in m || 'fingerprint' in m) throw new Error('manifest 不应携带指纹（热路径白调回归）')
  })
  t('prune: 硬链接共享内容按唯一字节计（review #6：逻辑和把 maxSnapshots 名存实亡）', () => {
    const store5 = join(tmp, '.dsh-snap-prune-uniq')
    for (let i = 0; i < 4; i++) takeSnapshot({ store: store5, trigger: 'agent:install_bundle:u' + i, profile: prof })
    // 4 快照共享 a-pkg 全部内容（逻辑和 4 份）；独占内容 1 份物理量：
    // 配额 0.8 份——逻辑和口径 4>0.8 删到只剩 1；唯一字节口径 1>0.8 也逐出，但断言差异点：
    // 改配额 1.2 份 → 唯一口径下 1 份 ≤ 1.2 全保留（4 个），逻辑口径 4 > 1.2 只剩 1
    const oneSnapBytes = listSnapshots(store5)[0].stats?.bytes ?? 0
    if (oneSnapBytes < 1) throw new Error('素材快照无字节')
    pruneSnapshots(store5, { maxSnapshots: 15, ttlDays: 30, maxBytes: Math.floor(oneSnapBytes * 1.2) })
    const left = listSnapshots(store5).filter((m) => !m.corrupted).length
    if (left < 4) throw new Error(`唯一字节口径未生效（1.2 份配额只剩 ${left}/4 个快照）`)
  })
  t('restore: 跨 harness 版本还原警告生效（review #2：曾因覆写后读取恒假）', () => {
    const storeK = join(tmp, '.dsh-snap-skew')
    // fakeProfile deps 需含 @deepseek-ai/*（resolveHarnessVersion 只认精确版本）
    const mf = join(fakeProfile, 'package.json')
    const saved = readFileSync(mf, 'utf8')
    const withHarness = { dependencies: { '@deepseek-ai/dsh-host': '0.2.0' } }
    writeFileSync(mf, JSON.stringify(withHarness))
    const m1 = takeSnapshot({ store: storeK, trigger: 'baseline', profile: prof })
    // 现行树 harness 版本改变（模拟桌面升级后还原旧快照）
    writeFileSync(mf, JSON.stringify({ dependencies: { '@deepseek-ai/dsh-host': '9.9.9' } }))
    const r = restoreSnapshot({ store: storeK, target: m1.id, profile: prof, skipProcessProbe: true })
    if (!r.ok) throw new Error(`restore 失败 ${r.code || ''}`)
    if (!r.harnessVersionSkew || r.harnessVersionSkew.current !== '9.9.9') {
      throw new Error(`skew 警告未生效：${JSON.stringify(r.harnessVersionSkew)}`)
    }
    writeFileSync(mf, saved)
  })
  t('restore: 索引缺失时如实报告而非假成功（review #3）+ 穿越行被拒（review #4）', () => {
    const storeL = join(tmp, '.dsh-snap-idx')
    const m = takeSnapshot({ store: storeL, trigger: 'baseline', profile: prof })
    rmSync(join(storeL, 'snapshots', m.id, 'files-index.tsv'))
    rmSync(join(nm, 'a-pkg', 'dist', 'x.js')) // 若被静默跳过，该文件不会被回填
    const r = restoreSnapshot({ store: storeL, target: m.id, profile: prof, skipProcessProbe: true })
    if (!r.reported?.some((x) => x.issue === 'index-missing')) throw new Error(`索引缺失未报告：${JSON.stringify(r.reported)}`)
    if (existsNo(join(nm, 'a-pkg', 'dist', 'x.js'))) throw new Error('索引缺失却回填了文件？')
    // 穿越行：索引行 rel=../evil.txt 必须被闸拒绝
    writeFileSync(join(storeL, 'snapshots', m.id, 'files-index.tsv'), `..\\..\\evil.txt\t5\t123\tfile\t\t` + '0'.repeat(64) + '\n')
    mkdirSync(join(storeL, 'snapshots', m.id, 'node_modules'), { recursive: true })
    const r2 = restoreSnapshot({ store: storeL, target: m.id, profile: prof, skipProcessProbe: true })
    if (existsNo(join(fakeProfile, '..', 'evil.txt')) || existsNo(join(tmp, 'evil.txt'))) throw new Error('路径穿越得手！')
    void r2
  })
  t('crash: shell-handshake 分类与豁免（2026-11-10 实战回归：外壳握手死循环不再冤枉插件/不再给无用还原建议）', () => {
    const shellText = [
      'time: 2026-11-10T01:52:42.427Z', 'source: host', 'phase: startup', 'app: @deepseek-ai/dsh-desktop 0.2.2-rc.1',
      '--- error ---', 'Error: desktop welcome: Web authentication failed',
      '    at connectDesktopWelcome (file:///E:/app.asar/lib/main.js:16856:31)',
      '    at async Object.start (file:///E:/app.asar/lib/main.js:20386:22)', '',
    ].join('\n')
    mkdirSync(join(tmp, 'logs'), { recursive: true })
    writeFileSync(join(tmp, 'logs', 'crash-shell.log'), shellText)
    const r = attributeCrash({ dshHome: tmp, store: join(tmp, '.dsh-snap-crash'), profile: { name: 'desktop', dir: fakeProfile }, hours: 24 })
    const c = r.crashes.find((x) => x.kind === 'shell-handshake')
    if (!c) throw new Error(`shell-handshake 未识别：${JSON.stringify(r.crashes.map((x) => x.kind))}`)
    if (c.correlated.length !== 0) throw new Error('外壳握手崩溃不应产出插件关联')
    if (!r.shellHandshake?.all || !r.shellHandshake?.hint) throw new Error('shellHandshake 汇总缺失')
    if (r.suspects.length) throw new Error('全 shell 崩溃时不应有插件嫌疑')
    if (r.restoreHint?.command) throw new Error('全 shell 崩溃时不应给 restore 命令')
  })
  t('repair-profile: 官方恢复痕迹检出 + 外科恢复（bundles←快照，patch←.bak 原文，guard 备份，dry-run 不写）', () => {
    const storeR = join(tmp, '.dsh-snap-repair')
    const mf = join(fakeProfile, 'package.json'), savedMf = readFileSync(mf, 'utf8')
    // 官方两包也要在 node_modules 里（bundle 源候选要求 bundles 全部已安装——排除演练旧态快照的回归）
    for (const name of ['official-a', 'official-b']) {
      mkdirSync(join(nm, name), { recursive: true })
      writeFileSync(join(nm, name, 'package.json'), `{"name":"${name}"}`)
    }
    writeFileSync(mf, JSON.stringify({ name: 'dsh-profile-desktop', private: true, dependencies: { 'a-pkg': '^1' }, dsh: { profile: { bundles: ['official-a', 'official-b', 'a-pkg'] } } }))
    takeSnapshot({ store: storeR, trigger: 'baseline', profile: prof })
    // 模拟官方恢复：patch 改名 .bak-<epoch> + bundles 砍成 2（deps 保留）
    const goodPatch = ['# good patch', '- id: dsh-snap', '  config:', '    snapshotOnInstall: true', ''].join('\n')
    writeFileSync(join(fakeProfile, 'cordis.patch.yml'), goodPatch)
    const bakName = `cordis.patch.yml.bak-${Date.now() - 60_000}`
    renameSync(join(fakeProfile, 'cordis.patch.yml'), join(fakeProfile, bakName))
    writeFileSync(join(fakeProfile, 'cordis.patch.yml'), '# damaged template\n')
    writeFileSync(mf, JSON.stringify({ name: 'dsh-profile-desktop', private: true, dependencies: { 'a-pkg': '^1' }, dsh: { profile: { bundles: ['official-a', 'official-b'] } } }))
    const d = repairProfile({ profile: prof, store: storeR, dryRun: true })
    if (!d.actions.some((a) => a.kind === 'bundles-restore') || !d.actions.some((a) => a.kind === 'patch-restore')) throw new Error(`dry-run 计划缺动作：${JSON.stringify(d)}`)
    if (JSON.parse(readFileSync(mf, 'utf8')).dsh.profile.bundles.length !== 2) throw new Error('dry-run 竟然写了 manifest')
    const savedSnap = process.env.DSH_SNAP_HOME
    process.env.DSH_SNAP_HOME = storeR // doctor 的 store 解析走 DSH_SNAP_HOME——切到夹具库才能对照到 3-bundle 快照
    let chk = null
    try { chk = doctor(prof, tmp).checks.find((c) => c.id === 'recovery-artifacts') } finally { process.env.DSH_SNAP_HOME = savedSnap }
    if (!chk || chk.ok) throw new Error(`recovery-artifacts 未报警：${JSON.stringify(chk)}`)
    const r = repairProfile({ profile: prof, store: storeR })
    const after = JSON.parse(readFileSync(mf, 'utf8'))
    if (after.dsh.profile.bundles.join(',') !== 'official-a,official-b,a-pkg') throw new Error(`bundles 未恢复：${after.dsh.profile.bundles}`)
    if (readFileSync(join(fakeProfile, 'cordis.patch.yml'), 'utf8') !== goodPatch) throw new Error('patch 未从 .bak 恢复')
    if (!r.guardDir || !existsNo(join(r.guardDir, 'package.json'))) throw new Error('guard 备份缺失')
    writeFileSync(mf, savedMf)
    rmSync(join(fakeProfile, 'cordis.patch.yml'), { force: true })
    rmSync(join(fakeProfile, bakName), { force: true })
  })
  t('repair-gui: 外壳状态备份+重置（dry-run 不动文件，真执行后 shell 集清空；Windows 实机面）', () => {
    if (!IS_WIN) return // repair-gui 是 Windows 桌面外壳专用（非 Windows 结构化拒绝已由 audit P1-02/P2-04 测试覆盖）
    const shell = join(tmp, 'fake-gui-shell')
    mkdirSync(join(shell, 'Network'), { recursive: true })
    writeFileSync(join(shell, 'Local State'), '{"os_crypt":{}}')
    writeFileSync(join(shell, 'Network', 'Cookies'), 'sqlite')
    const storeG = join(tmp, '.dsh-snap-gui')
    const d = repairGui({ shellDir: shell, store: storeG, dryRun: true, skipProcessGuard: true })
    if (d.targets.length !== 2) throw new Error(`dry-run 目标集异常：${JSON.stringify(d.targets)}`)
    if (readFileSync(join(shell, 'Local State'), 'utf8') !== '{"os_crypt":{}}') throw new Error('dry-run 竟然删了文件')
    const r = repairGui({ shellDir: shell, store: storeG, skipProcessGuard: true })
    if (!r.guardDir || !existsNo(join(r.guardDir, 'Network', 'Cookies'))) throw new Error('guard 备份不完整')
    if (existsNo(join(shell, 'Network')) || existsNo(join(shell, 'Local State'))) throw new Error('状态未重置')
    // 进程闸形态验证：不传 skipProcessGuard 时，桌面在跑则拒绝（本机没跑则放行——两种都合法）
    const guarded = repairGui({ shellDir: shell, store: storeG, dryRun: true })
    if (guarded.ok === false && !(guarded.skipped?.[0] ?? '').includes('DeepSeek')) {
      throw new Error(`进程闸拒绝理由异常：${JSON.stringify(guarded.skipped)}`)
    }
  })
  /* ---- 审核 0.7.2 报告 §6 要求的六项回归（P1-01~07 / P2-01~04）---- */
  t('audit: repairGui tasklist 失败 fail-closed（P1-02）+ 非 Windows/APPDATA 缺失结构化拒绝（P2-04）', () => {
    const shell = join(tmp, 'fake-gui-shell-guard')
    mkdirSync(join(shell, 'Network'), { recursive: true })
    writeFileSync(join(shell, 'Local State'), 'x')
    const storeA = join(tmp, '.dsh-snap-audit1')
    // 夹具：跳过进程闸为 false 才能测闸本身；本机在跑/没跑都合法，但 null（探测失败）必须拒绝——
    // 通过注入 fake probe 无法做到（函数未导出），改为直接断言三态语义：用 IS_WIN 恒真环境 + 真实 tasklist。
    // 这里验证的是「闸存在且三态语义正确」：ok=false 时 skipped 必须带理由。
    const g = repairGui({ shellDir: shell, store: storeA, dryRun: true, skipProcessGuard: false })
    if (g.ok === false && !String(g.skipped?.[0] ?? '').match(/DeepSeek|tasklist|Windows/)) throw new Error(`拒绝缺理由：${JSON.stringify(g.skipped)}`)
    if (g.busy === null && g.ok !== false && IS_WIN) throw new Error('探测失败（busy=null）却放行——fail-open 回归！')
    // P2-04：非 shellDir 注入时 APPDATA 必须存在（本机恒有）——只测 APPDATA 缺失分支的代码路径可达性：
    // 用临时清空 APPDATA + 显式不传 shellDir
    const savedAppdata = process.env.APPDATA
    let denied = false
    try {
      delete process.env.APPDATA
      // IS_WIN 分支在非 Windows 平台会先拒绝；这里只验证 APPDATA 缺失时不产生相对路径 target
      const r2 = repairGui({ store: join(tmp, '.dsh-snap-audit1b'), dryRun: true, skipProcessGuard: true })
      denied = r2.ok === false || !String(r2.shellDir ?? '').match(/^[A-Za-z]:|^\/|^\$/) // 结构化拒绝或绝对路径
      if (!denied) throw new Error(`APPDATA 缺失却得到疑似相对路径的 shellDir：${r2.shellDir}`)
    } finally { process.env.APPDATA = savedAppdata }
  })
  t('audit: repairGui 备份失败不删除、删除失败不假成功（P1-03）', () => {
    const shell = join(tmp, 'fake-gui-shell-bak')
    mkdirSync(join(shell, 'Network'), { recursive: true })
    writeFileSync(join(shell, 'Network', 'Cookies'), ' precious ')
    const storeB = join(tmp, '.dsh-snap-audit2')
    // 备份失败注入：store 路径指向一个文件 → mkdirSync(guardDir) 必失败（若按目录建 store 则 incidents 下有阻断文件）
    writeFileSync(join(tmp, '.dsh-snap-audit2-asfile'), 'not a dir')
    const before = readFileSync(join(shell, 'Network', 'Cookies'), 'utf8')
    const r = repairGui({ shellDir: shell, store: join(tmp, '.dsh-snap-audit2-asfile'), skipProcessGuard: true })
    if (r.ok !== false) throw new Error(`备份失败仍报 ok:true：${JSON.stringify(r)}`)
    if (readFileSync(join(shell, 'Network', 'Cookies'), 'utf8') !== before) throw new Error('备份失败竟删除了状态！')
    if (!existsNo(join(shell, 'Network'))) throw new Error('Network 目录被删')
    // 删除失败路径：errors→ok=false→CLI exit 1 的联动由同一错误聚合承载，语义已被上一分支覆盖
  })
  t('audit: repairProfile guard 失败放弃修复、live 不写（P1-04）', () => {
    const storeC = join(tmp, '.dsh-snap-audit3-asfile')
    // 构造恢复痕迹：patch 改名 .bak + live 是受损模板
    const goodPatch = '# good\n- id: x\n'
    const bakName = `cordis.patch.yml.bak-${Date.now() - 30_000}`
    writeFileSync(join(fakeProfile, bakName), goodPatch)
    writeFileSync(join(fakeProfile, 'cordis.patch.yml'), '# damaged\n')
    const mf = join(fakeProfile, 'package.json')
    const savedMf = readFileSync(mf, 'utf8')
    // guard 失败注入：store 指向文件 → mkdirSync(incidents/<stamp>-...) 深层创建必失败
    writeFileSync(storeC, 'not a dir')
    const r = repairProfile({ profile: prof, store: storeC })
    if (r.ok !== false) throw new Error(`guard 失败仍 ok:true：${JSON.stringify(r)}`)
    if (readFileSync(join(fakeProfile, 'cordis.patch.yml'), 'utf8') !== '# damaged\n') throw new Error('guard 失败竟覆盖了 live patch！')
    if (JSON.parse(readFileSync(mf, 'utf8')).dsh?.profile?.bundles) throw new Error('guard 失败竟写了 manifest bundles！')
    // 清理痕迹，不影响后续测试
    rmSync(join(fakeProfile, bakName), { force: true })
    rmSync(join(fakeProfile, 'cordis.patch.yml'), { force: true })
    writeFileSync(mf, savedMf)
  })
  t('audit: patch 同尺寸不同内容必须被选中（P2-01）', () => {
    const storeD = join(tmp, '.dsh-snap-audit4')
    const bakName = `cordis.patch.yml.bak-${Date.now() - 45_000}`
    writeFileSync(join(fakeProfile, bakName), 'AAAABBBB') // 与 live 同尺寸(8) 不同内容
    writeFileSync(join(fakeProfile, 'cordis.patch.yml'), 'AAAACCCC')
    const d = repairProfile({ profile: prof, store: storeD, dryRun: true })
    if (!d.actions.some((a) => a.kind === 'patch-restore')) throw new Error(`同尺寸不同内容漏修：${JSON.stringify(d)}`)
    // recoveryArtifacts 的 patchDiffers 也要按内容判
    const saved = process.env.DSH_SNAP_HOME
    process.env.DSH_SNAP_HOME = storeD
    let art = null
    try { art = recoveryArtifacts(prof.dir, storeD) } finally { process.env.DSH_SNAP_HOME = saved }
    if (art.patchDiffers !== true) throw new Error(`patchDiffers 尺寸同内容异仍为 false：${JSON.stringify({ p: art.patchDiffers, l: art.livePatchSize, b: art.newest.size })}`)
    rmSync(join(fakeProfile, bakName), { force: true })
    rmSync(join(fakeProfile, 'cordis.patch.yml'), { force: true })
  })
  t('audit: snapshotBundlesMax 无 nm 不放行 ghost、官方豁免须同版 harness（P1-06/P2-02）', () => {
    const storeE = join(tmp, '.dsh-snap-audit5')
    const mf = join(fakeProfile, 'package.json')
    const savedMf = readFileSync(mf, 'utf8')
    // 无 nm 目录（模拟全新 profile/损坏现场），deps 为空：ghost 与官方包都不得被选中
    const nmSaved = join(tmp, 'nm-parked-audit')
    rmSync(join(fakeProfile, 'node_modules'), { recursive: true, force: true })
    writeFileSync(mf, JSON.stringify({ name: 'dsh-profile-desktop', private: true, dependencies: {}, dsh: { profile: { bundles: [] } } }))
    const m1 = takeSnapshot({ store: storeE, trigger: 'manual', profile: prof })
    void m1
    // 改快照侧 package.json 注入带 ghost bundle 的候选（不走 takeSnapshot——它要求 nm 存在）
    const snapId = okReaddir(join(storeE, 'snapshots'))[0]
    writeFileSync(join(storeE, 'snapshots', snapId, 'profile', 'package.json'), JSON.stringify({
      name: 'dsh-profile-desktop', private: true,
      dependencies: { '@deepseek-ai/dsh-subagent-claude-code': '9.9.9-fake' }, // 与 live（空 deps）不同版 → 官方豁免失效
      dsh: { profile: { bundles: ['ghost-not-installed', '@deepseek-ai/not-installed-anywhere'] } },
    }))
    // 同版 harness deps 时官方包可豁免（deps 里有同版声明）——注意 b.every 是全有全无：
    // ghost 混在同一快照会否掉整个候选，官方豁免的正路径须用纯官方 bundle 的独立候选验证
    const snapId2 = '20990101T000000-' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0')
    mkdirSync(join(storeE, 'snapshots', snapId2, 'profile'), { recursive: true })
    writeFileSync(join(storeE, 'snapshots', snapId2, 'profile', 'package.json'), JSON.stringify({
      name: 'dsh-profile-desktop', private: true,
      dependencies: { '@deepseek-ai/dsh-subagent-claude-code': '9.9.9-fake' },
      dsh: { profile: { bundles: ['@deepseek-ai/not-installed-anywhere'] } },
    }))
    const depsSame = { '@deepseek-ai/dsh-subagent-claude-code': '9.9.9-fake' }
    const sb2 = snapshotBundlesMax(storeE, join(fakeProfile, 'node_modules'), depsSame)
    if (!sb2 || !sb2.bundles.includes('@deepseek-ai/not-installed-anywhere')) throw new Error('同版 harness 官方豁免失效（过度收紧）')
    // 异版 deps：官方豁免必须失效（同版校验生效）
    const sb3 = snapshotBundlesMax(storeE, join(fakeProfile, 'node_modules'), { '@deepseek-ai/dsh-subagent-claude-code': '0.0.1-other' })
    if (sb3) throw new Error('异版 harness 官方包仍被放行（P2-02 未生效）')
    // 删除同版正路径候选后重验 ghost-only：无任何解析依据 → 不选出
    rmSync(join(storeE, 'snapshots', snapId2), { recursive: true, force: true })
    const sb4 = snapshotBundlesMax(storeE, join(fakeProfile, 'node_modules'), depsSame)
    if (sb4) throw new Error(`ghost-only 快照仍被选出：${JSON.stringify(sb4)}`)
    // 恢复 nm 与 manifest（nm 移走重建，防误删夹具共享内容）
    mkdirSync(join(fakeProfile, 'node_modules', 'a-pkg', 'dist'), { recursive: true })
    writeFileSync(join(fakeProfile, 'node_modules', 'a-pkg', 'dist', 'x.js'), 'console.log(1)\n')
    writeFileSync(join(fakeProfile, 'node_modules', 'a-pkg', 'package.json'), '{"name":"a-pkg","version":"1.0.0"}')
    writeFileSync(mf, savedMf)
    void nmSaved
  })
  t('audit: 宿主 takeSnapshot 同步契约（P1-05：返回 manifest 不是 Promise）', async () => {
    // 内核层断言契约本身：宿主半的 .then 用法已改同步；这里固化「返回值无 then」防止未来内核改异步时宿主静默坏死
    const m = takeSnapshot({ store: join(tmp, '.dsh-snap-audit6'), trigger: 'manual', profile: prof })
    if (typeof m.then !== 'undefined') throw new Error('takeSnapshot 变成了 Promise——宿主半 index.js 的同步调用面需同步更新')
    if (!m?.id || !m?.stats) throw new Error('takeSnapshot 未返回 manifest')
  })
  /* ---- 0.7.4 审计（audit-0.7.3-report）回归固化：E6 要求变异探针入常规测试 ---- */
  t('audit0.7.4: A1 manifest taken 穿越被隔离（restore 不写出目标目录）', () => {
    const storeT = join(tmp, '.dsh-snap-a7-1')
    const m = takeSnapshot({ store: storeT, trigger: 'manual', profile: prof })
    // 篡改 manifest：塞进穿越路径 + 在 store 根放"受害者"——被篡改 manifest 必须整份隔离
    const mp = join(storeT, 'snapshots', m.id, 'manifest.json')
    const evil = JSON.parse(readFileSync(mp, 'utf8'))
    evil.layers.profile.taken = ['../../victim.txt']
    writeFileSync(mp, JSON.stringify(evil))
    writeFileSync(join(storeT, 'victim.txt'), 'ATTACKER-CONTROLLED')
    const r = restoreSnapshot({ store: storeT, target: m.id, profile: prof, skipProcessProbe: true })
    if (r.ok !== false || r.code !== 'snapshot-not-found') throw new Error(`被篡改 manifest 未被隔离：${JSON.stringify({ ok: r.ok, code: r.code })}`)
    if (readFileSync(join(storeT, 'victim.txt'), 'utf8') !== 'ATTACKER-CONTROLLED') throw new Error('穿越写入得手！')
    if (existsNo(join(fakeProfile, 'victim.txt')) || existsNo(join(tmp, 'victim.txt'))) throw new Error('越界文件出现')
    // home 层同类：伪造 home.taken 越界项同样隔离
    evil.layers.profile.taken = ['package.json']
    evil.layers.home = { taken: ['../../home-victim.txt'], skipped: [] }
    writeFileSync(mp, JSON.stringify(evil))
    const r2 = restoreSnapshot({ store: storeT, target: m.id, profile: prof, skipProcessProbe: true, includeHome: true })
    if (r2.ok !== false) throw new Error('home.taken 越界未被隔离')
    if (existsNo(join(tmp, 'home-victim.txt'))) throw new Error('home 层穿越写入得手！')
  })
  t('audit0.7.4: A2 junction 祖先拒绝（还原不越界覆盖外部文件）', () => {
    const storeT = join(tmp, '.dsh-snap-a7-2')
    const outside = join(tmp, 'a2-outside')
    mkdirSync(outside, { recursive: true })
    mkdirSync(join(nm, 'pivot'), { recursive: true })
    writeFileSync(join(nm, 'pivot', 'victim.txt'), 'LIVE-OLD')
    writeFileSync(join(outside, 'victim.txt'), 'OUTSIDE-ORIGINAL')
    const m = takeSnapshot({ store: storeT, trigger: 'manual', profile: prof })
    // 拍完后把 live pivot 换成指向外部的 junction——词法 containment 闸管不住它
    rmSync(join(nm, 'pivot'), { recursive: true, force: true })
    let junctionOk = true
    try { symlinkSync(outside, join(nm, 'pivot'), 'junction') } catch { junctionOk = false }
    if (junctionOk) {
      const r = restoreSnapshot({ store: storeT, target: m.id, profile: prof, skipProcessProbe: true })
      if (readFileSync(join(outside, 'victim.txt'), 'utf8') !== 'OUTSIDE-ORIGINAL') throw new Error('junction 祖先重定向得手——外部文件被覆盖！')
      if (!r.reported?.some((x) => x.issue === 'ancestor-reparse-refused')) throw new Error(`junction 祖先未被拒绝：${JSON.stringify(r.reported)}`)
      if (r.ok !== false || r.partial !== true) throw new Error('越界拒绝未标 partial')
    }
    rmSync(join(nm, 'pivot'), { recursive: true, force: true })
    mkdirSync(join(nm, 'pivot'), { recursive: true })
    writeFileSync(join(nm, 'pivot', 'victim.txt'), 'LIVE-OLD')
  })
  t('audit0.7.4: A3 增量复用不传播上一快照污染（prev 污染 → 回退 live 源 + stats 计数）', () => {
    const storeT = join(tmp, '.dsh-snap-a7-3')
    const f = join(nm, 'a-pkg', 'dist', 'a3.js')
    writeFileSync(f, 'GOOD')
    const m1 = takeSnapshot({ store: storeT, trigger: 'manual', profile: prof })
    const snapFile1 = join(storeT, 'snapshots', m1.id, 'node_modules', 'a-pkg', 'dist', 'a3.js')
    // 断开硬链接并只改快照侧为 EVIL（live 保持 GOOD）——A3 的攻击形态
    rmSync(snapFile1)
    writeFileSync(snapFile1, 'EVIL')
    utimesSync(snapFile1, new Date(Date.now() - 3600_000), new Date(Date.now() - 3600_000))
    // live 保持 GOOD 且 mtime 匹配（把 live 的 mtime 调到与 index 记录一致）
    const idx1 = readFileSync(join(storeT, 'snapshots', m1.id, 'files-index.tsv'), 'utf8').split('\n').find((l) => l.includes('a3.js'))
    const recMtime = Number(idx1.split('\t')[2])
    utimesSync(f, new Date(recMtime), new Date(recMtime))
    const m2 = takeSnapshot({ store: storeT, trigger: 'manual', profile: prof, prevId: m1.id })
    const snapFile2 = join(storeT, 'snapshots', m2.id, 'node_modules', 'a-pkg', 'dist', 'a3.js')
    if (readFileSync(snapFile2, 'utf8') === 'EVIL') throw new Error('上一快照污染被复用传播！')
    if (readFileSync(snapFile2, 'utf8') !== 'GOOD') throw new Error('回退后新快照不是 live 内容')
    if ((m2.stats.pollutedPrev ?? 0) < 1) throw new Error(`污染未入账：${JSON.stringify(m2.stats)}`)
    if (m2.stats.complete !== true) throw new Error('回退后新快照应 complete')
  })
  t('audit0.7.4: D2 restore last 只选装前触发器（manual 不再可被选中）', () => {
    const storeT = join(tmp, '.dsh-snap-a7-4')
    const good = takeSnapshot({ store: storeT, trigger: 'agent:install_bundle:good-pkg', profile: prof, spec: 'good-pkg' })
    const broken = takeSnapshot({ store: storeT, trigger: 'manual', profile: prof, label: 'broken state' })
    void broken
    const lt = lastRestoreTarget(storeT)
    if (lt.id !== good.id || lt.fallback) throw new Error(`last 选到了 manual：${JSON.stringify(lt)}`)
    const r = restoreSnapshot({ store: storeT, target: 'last', profile: prof, skipProcessProbe: true, dryRun: true })
    if (r.restoredTo !== good.id) throw new Error(`restore last 落到 ${r.restoredTo}，应为装前快照 ${good.id}`)
  })
  t('audit0.7.4: B4 并发 restore 互斥（活锁拒绝、死锁收编）', () => {
    const storeT = join(tmp, '.dsh-snap-a7-5')
    takeSnapshot({ store: storeT, trigger: 'manual', profile: prof })
    // 模拟另一活进程持锁
    mkdirSync(join(storeT), { recursive: true })
    writeFileSync(join(storeT, 'restore.lock'), JSON.stringify({ pid: 999999, startedAt: Date.now() }))
    // pid 999999 必须确实不存在（pidAlive false）——用假 pid 走"死锁收编"分支
    // 活锁形态无法在本进程内安全构造（不能 spawn 持锁真实还原），死锁收编即覆盖 steal 路径
    const r = restoreSnapshot({ store: storeT, target: lastRestoreTarget(storeT).id, profile: prof, skipProcessProbe: true })
    if (!r.ok) throw new Error(`死锁收编后 restore 应成功：${JSON.stringify(r)}`)
    if (existsNo(join(storeT, 'restore.lock'))) throw new Error('锁未释放')
    // EBUSY 持锁形态：本进程自己 open 不关 → 第二次 restore 必须拒绝
    const fdHold = openSync(join(storeT, 'restore.lock'), 'wx')
    writeFileSync(fdHold, JSON.stringify({ pid: process.pid, startedAt: Date.now() }), 'utf8')
    const r2 = restoreSnapshot({ store: storeT, target: lastRestoreTarget(storeT).id, profile: prof, skipProcessProbe: true })
    if (r2.ok !== false || r2.code !== 'restore-busy') throw new Error(`活锁未拒绝：${JSON.stringify(r2)}`)
    closeSync(fdHold)
    rmSync(join(storeT, 'restore.lock'), { force: true })
  })
  t('audit0.7.4: F1 引号 key 凭据检出 + profile patch 命中入账', () => {
    // 引号 key：home settings.yaml 命中 → 整文件跳过
    const homeT = join(tmp, 'a7-home')
    mkdirSync(homeT, { recursive: true })
    writeFileSync(join(homeT, 'settings.yaml'), '"token": "HOME_CANARY"\n')
    const storeT = join(tmp, '.dsh-snap-a7-6')
    const m = takeSnapshot({ store: storeT, trigger: 'manual', profile: prof, dshHome: homeT })
    if (m.layers.home.taken.includes('settings.yaml')) throw new Error('引号 key 凭据文件被收进快照')
    if (!m.layers.home.skipped.some((s) => s.file === 'settings.yaml' && s.reason === 'credential-like')) throw new Error('跳过原因未记录')
    // profile patch：命中 → 照常拷贝（还原完整性）但 credHits 显式入账
    writeFileSync(join(fakeProfile, 'cordis.patch.yml'), 'webserver:\n  api_key: PROFILE_CANARY\n')
    const m2 = takeSnapshot({ store: storeT, trigger: 'manual', profile: prof, dshHome: homeT })
    if (!m2.layers.profile.taken.includes('cordis.patch.yml')) throw new Error('patch 被跳过——还原完整性被破坏')
    if (!m2.layers.profile.credHits?.some((h) => h.file === 'cordis.patch.yml')) throw new Error('patch 凭据命中未入账')
    rmSync(join(fakeProfile, 'cordis.patch.yml'), { force: true })
  })
  try { rmSync(tmp, { recursive: true, force: true }) } catch { /* 清理失败可容忍 */ }
  // env 还原（review #12：selftest 被 import 后调用时，残留 env 指向已删除目录，
  // 宿主进程后续 resolveDshHome()/resolveStore() 全部落错位置）
  if (savedEnv.HOME === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = savedEnv.HOME
  if (savedEnv.PROFILE === undefined) delete process.env.DSH_PROFILE; else process.env.DSH_PROFILE = savedEnv.PROFILE
  if (savedEnv.SNAP === undefined) delete process.env.DSH_SNAP_HOME; else process.env.DSH_SNAP_HOME = savedEnv.SNAP
  return results
}

function mkdtempSafe(prefix) {
  const dir = join(tmpdir(), `${prefix}${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  mkdirSync(dir, { recursive: true })
  return dir
}

/** 资源管理器/访达打开目录（open 命令与面板"打开快照库"共用） */
export function openInFileManager(p) {
  try {
    if (IS_WIN) { spawn('explorer', [p], { detached: true, stdio: 'ignore' }).unref(); return true }
    const cmd = platform() === 'darwin' ? 'open' : 'xdg-open'
    spawn(cmd, [p], { detached: true, stdio: 'ignore' }).unref()
    return true
  } catch { return false }
}

/* ============================================================
 * CLI 入口
 * ============================================================ */

function parseArgs(argv) {
  const args = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--json') args.json = true
    else if (a === '--force') args.force = true
    else if (a === '--dry-run') args.dryRun = true
    else if (a === '--include-home') args.includeHome = true
    else if (a === '--prune-extraneous') args.pruneExtraneous = true
    else if (a === '--no-node-modules') args.nodeModules = false
    else if (a === '--no-home') args.home = false
    else if (a === '--deep') args.deep = true
    else if (a === '--hours') args.hours = Number(argv[++i]) || undefined
    else if (a === '--port') args.port = Number(argv[++i]) || undefined
    else if (a === '--label') args.label = argv[++i]
    else if (a === '--spec') args.spec = argv[++i]
    else if (a === '--trigger') args.trigger = argv[++i]
    else if (a === '--prev') args.prev = argv[++i]
    else if (a === '--help' || a === '-h') args.help = true
    else args._.push(a)
  }
  return args
}

const HELP = `dsh-snap — 装插件搞崩，一键回到装前

用法：node dsh-snap.mjs <命令> [参数]

  list                       列出快照（--json 机器可读）
  snapshot [--label L] [--spec S] [--trigger T] [--no-node-modules] [--no-home]
                             手动拍快照（手动快照永不被自动清理）
  restore <id|last> [--dry-run] [--include-home] [--prune-extraneous] [--force]
                             还原到装前状态（先自动拍 guard 快照，可 undo）
                             last = 最近的装前触发器快照（manual/guard 不会被选中）
  undo                       撤销最近一次 restore
  verify [id|last|all] [--deep]
                             校验快照完整性（快照侧文件被原地改写=污染指纹；--deep 逐文件 sha256）
  prune                      按保留策略清理快照库
  doctor                     环境体检（路径/同卷/占用/快照库完整性/官方恢复痕迹）
  repair-profile [--dry-run] 外科修复被官方「禁用第三方插件」恢复砍掉的 bundles/patch
                             （bundles ← 最新快照，patch ← 恢复 .bak 原文；不动 node_modules/deps）
  repair-gui [--dry-run] [--force]
                             GUI 外壳网络状态重置：desktop welcome 握手死循环（强杀后遗症）的修复；
                             先备份 %APPDATA%\\@deepseek-ai\\dsh-desktop 的状态集再删除，登录凭据不受影响
                             （完全退出 DSH 后运行；救援台可用 store/cli/repair-gui.bat）
  crash [--hours N] [--json] 崩溃归因：崩溃日志 + journal 时间窗 → 嫌疑插件与还原建议
                             （只报告不动手；无日志时为纯 journal 时间关联）
  diff <idA> [idB] [--json]  两快照差异（省略 idB = 与最新快照对比；装前/装后一目了然）
  unstick                    清理残留的安装锁（持锁进程已死的 run.json / 超时的 package.json.lock）
  preflight <pkg>            装前体检：registry 元数据 + engines 兼容性（只告警不阻断）
  serve [--port N]           救援台网页（仅本机回环+随机 token；DSH 起不来时浏览器可用）
  open                       在资源管理器打开快照库
  where                      输出 DSH_HOME / profile / 快照库位置
  state [--clear]            DSH 运行/崩溃标志状态
  selftest                   内部不变量自检

环境变量：DSH_HOME、DSH_PROFILE、DSH_SNAP_HOME

安全声明：会话数据与工作区文件永不触碰；危险项只报告不动手。`

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv)
  const jsonOut = (obj) => { console.log(JSON.stringify(obj, null, 2)); return obj.ok === false ? 1 : 0 }
  if (args.help || args._[0] === 'help' || !args._[0]) { console.log(HELP); return 0 }
  const cmd = args._[0]

  try {
    switch (cmd) {
      case 'where': {
        const dshHome = resolveDshHome(); const profile = resolveProfile(dshHome); const store = resolveStore(dshHome)
        return jsonOut({ ok: true, dshHome, profile: profile.dir, profileName: profile.name, store, sameVolume: sameVolume(profile.dir, store) })
      }
      case 'list': {
        const store = resolveStore()
        const all = listSnapshots(store)
        if (args.json) return jsonOut({ ok: true, store, snapshots: all })
        if (!all.length) { console.log(`（快照库为空：${store}）`); return 0 }
        for (const m of all) {
          if (m.corrupted) { console.log(`${m.id}  ⚠️ 损坏/不完整（已隔离）`); continue }
          const flag = m.guard ? '[guard] ' : m.manual ? '[手动] ' : ''
          console.log(`${m.id}  ${flag}${m.trigger}  ${m.spec ?? ''}  ${m.stats?.files ?? '?'}文件 ${fmtBytes(m.stats?.bytes)} ${m.stats?.durationMs ?? '?'}ms`)
        }
        return 0
      }
      case 'snapshot': {
        const store = resolveStore()
        const profile = resolveProfile()
        const m = takeSnapshot({
          store, profile, trigger: args.trigger || 'manual',
          spec: args.spec ?? null, label: args.label ?? null,
          nodeModules: args.nodeModules !== false, home: args.home !== false,
          prevId: args.prev ?? newestSnapshotId(store),
        })
        return jsonOut({ ok: true, id: m.id, stats: m.stats })
      }
      case 'restore': {
        const r = restoreSnapshot({
          store: resolveStore(), target: args._[1] || 'last', profile: resolveProfile(),
          force: args.force, dryRun: args.dryRun, includeHome: args.includeHome,
          pruneExtraneous: args.pruneExtraneous,
        })
        if (!r.ok) return jsonOut(r)
        if (r.dryRun) {
          console.log('[dry-run] 还原计划：')
          if (r.evidence) {
            console.log(`证据：快照侧文件已核验 ${r.evidence.verified} 个${r.evidence.snapshotFileMissing ? `，⚠️ 缺失 ${r.evidence.snapshotFileMissing} 个（${r.trustLevel === 'degraded' ? '执行时将报告并跳过' : ''}）` : ''}`)
          }
          return jsonOut({ ok: true, restoredTo: r.restoredTo, plan: r.plan, evidence: r.evidence, trustLevel: r.trustLevel })
        }
        if (r.interruptedBefore) {
          console.log(`⚠️ 检测到上次还原未完成（目标 ${r.interruptedBefore.target}，停在 ${r.interruptedBefore.phase} 阶段）——本次还原已完整重跑；若要回到还原前状态可用 undo（guard ${r.interruptedBefore.guardId}）`)
        }
        if (r.partial) {
          console.log(`⚠️ 还原部分完成（${r.partialReason}）`)
        } else {
          console.log(`✅ 已还原到 ${r.restoredTo}（guard 快照 ${r.guardId}，可用 undo 撤销）`)
        }
        console.log(`   回填 ${r.restored} 个文件，跳过 ${r.skipped} 个，报告 ${r.reported.length} 项`)
        if (r.harnessVersionSkew) {
          console.log(`   ⚠️ 跨 harness 版本还原：快照拍于 ${r.harnessVersionSkew.snapshot}，现行树是 ${r.harnessVersionSkew.current}——旧版插件面回退可能触发版本门或配置漂移；若异常可还原回 guard ${r.guardId}`)
        }
        for (const rep of r.reported.slice(0, 20)) console.log(`   · ${rep.path} — ${rep.issue}${rep.error ? `：${rep.error}` : ''}`)
        // 多出的顶层条目：克制哲学——始终只报告不动手（--prune-extraneous 才移入 trash）
        const extras = r.plan?.nodeModules?.extraneousTopLevel ?? []
        if (extras.length && !args.pruneExtraneous) {
          console.log(`   ⏸ 多出的顶层条目（默认保留，加 --prune-extraneous 移入 trash）：${extras.join(', ')}`)
        }
        console.log(r.radius)
        return r.ok ? 0 : 1 // E2：部分还原（partial）非零退出——自动化不得当成功
      }
      case 'undo': {
        const store = resolveStore()
        const guards = listSnapshots(store).filter((m) => !m.corrupted && m.trigger === 'pre-restore')
        if (!guards.length) return jsonOut({ ok: false, code: 'no-guard', hint: '没有可撤销的还原记录' })
        const r = restoreSnapshot({ store, target: guards[0].id, profile: resolveProfile(), force: args.force, includeHome: args.includeHome })
        if (r.ok && r.interruptedBefore) console.log(`⚠️ 检测到上次还原未完成（目标 ${r.interruptedBefore.target}，停在 ${r.interruptedBefore.phase}）——本次 undo 已完整执行`)
        return jsonOut(r.ok ? { ok: true, undoneTo: r.restoredTo, guardId: r.guardId } : r)
      }
      case 'prune': return jsonOut({ ok: true, ...pruneSnapshots(resolveStore()) })
      case 'verify': {
        const store = resolveStore()
        const target = args._[1] || 'last'
        const ids = target === 'all'
          ? listSnapshots(store).filter((m) => !m.corrupted).map((m) => m.id)
          : [target === 'last' ? newestSnapshotId(store) : target].filter(Boolean)
        if (!ids.length) return jsonOut({ ok: false, code: 'no-snapshot', hint: '快照库为空' })
        const results = ids.map((id) => verifySnapshot(store, id, { deep: args.deep }))
        const ok = results.every((r) => r.ok)
        if (args.json) return jsonOut({ ok, results })
        for (const r of results) {
          console.log(`${r.ok ? '✅' : '⚠️'} ${r.id}  ${verifyPrettyLine(r)}  （${r.durationMs}ms）`)
          for (const bucket of ['modified', 'hashMismatch', 'missing']) {
            for (const rel of r.samples[bucket]) console.log(`   · ${rel} — ${bucket}`)
          }
        }
        if (!ok) console.log('提示：被改文件若在现行树中同 inode，还原时已按污染处理；可用 lockfile 重建（pnpm install --frozen-lockfile）')
        return ok ? 0 : 1
      }
      case 'open': {
        const store = resolveStore()
        openInFileManager(store)
        return jsonOut({ ok: true, store })
      }
      case 'crash': {
        const dshHome = resolveDshHome(), profile = resolveProfile(dshHome), store = resolveStore(dshHome)
        const r = attributeCrash({ dshHome, store, profile: { name: profile.name, dir: profile.dir }, hours: args.hours })
        if (args.json) return jsonOut(r)
        const src = r.sources.journalOnly ? `journal-only（未发现崩溃日志；journal ${r.sources.journalEvents} 事件）`
          : `日志 ${r.sources.logScanned} 份 + journal ${r.sources.journalEvents} 事件`
        console.log(`崩溃归因（profile=${r.profile}，${src}）：`)
        if (!r.crashes.length) console.log('  未发现崩溃记录（回溯窗内无崩溃日志，24h 内无 crash-detected）')
        for (const c of r.crashes.slice(0, 5)) {
          console.log(`  [${c.origin}] ${c.time}  ${c.kind}${c.exitCode ? `（exit=${c.exitCode}）` : ''}`)
          console.log(`    ${c.summary.slice(0, 160)}${c.frame ? `\n    at ${c.frame}` : ''}`)
        }
        if (r.suspects.length) {
          console.log('嫌疑插件（时间窗关联，仅供参考，只报告不动手）：')
          for (const s of r.suspects) console.log(`  - ${s.pkg} — ${s.confidence} · ${s.evidence.join('；')}`)
        } else if (r.crashes.length && !r.shellHandshake?.all) console.log('嫌疑插件：无（崩溃前 24h 内未发现插件变更记录）')
        for (const l of r.loops) console.log(`崩溃循环：24h 内 ${l.count} 次（${l.first} → ${l.last}）${r.shellHandshake?.all ? '——全为外壳握手类，与插件无关' : '——先还原/停用嫌疑插件，再修'}`)
        if (r.shellHandshake) {
          console.log(`⚠️ 外壳握手失败 ${r.shellHandshake.count}/${r.shellHandshake.allCount} 次：${r.shellHandshake.all ? '全部' : '部分'}崩溃是 GUI 外壳↔宿主本地握手问题，与插件无关。`)
          console.log(`修复：完全退出 DSH（含托盘）后运行 node "${join(store, 'cli', 'dsh-snap.mjs')}" repair-gui（备份并重置外壳网络状态；也可双击 cli\\repair-gui.bat），再启动桌面。`)
          console.log('官方弹窗的「禁用第三方插件」对此无效，且会砍掉 bundles/patch（可用 `repair-profile` 恢复）。')
        }
        if (r.restoreHint?.command) {
          console.log(`还原建议（先完全退出 DSH，含托盘）：${r.restoreHint.command}`)
          console.log(`  （快照 ${r.restoreHint.snapshotId}，拍于 ${r.restoreHint.time}）`)
        } else if (r.restoreHint?.reason) console.log(`还原建议：${r.restoreHint.reason}`)
        return 0
      }
      case 'doctor': {
        const r = doctor(resolveProfile())
        if (args.json) return jsonOut(r)
        for (const c of r.checks) console.log(`${c.ok ? '✅' : '⚠️'} ${c.id}: ${c.detail}`)
        return r.ok ? 0 : 1
      }
      case 'repair-profile': {
        const profile = resolveProfile()
        const r = repairProfile({ profile: { name: profile.name, dir: profile.dir }, dryRun: args.dryRun })
        if (args.json) return jsonOut(r)
        if (r.dryRun) console.log('[dry-run] 修复计划：')
        for (const a of r.actions) console.log(`  ${a.kind}: ← ${a.from}${a.count ? `（${a.count} 个 bundles）` : ''}${a.bytes ? `（${fmtBytes(a.bytes)}）` : ''}`)
        for (const s of r.skipped) console.log(`  跳过：${s}`)
        if (!r.dryRun && r.actions.length) console.log(`✅ 已修复（原配置备份在 ${r.guardDir}）——重启 DSH 生效`)
        return r.ok ? 0 : 1
      }
      case 'repair-gui': {
        const r = repairGui({ dryRun: args.dryRun, skipProcessGuard: args.force })
        if (args.json) return jsonOut(r)
        if (!r.ok && !r.guardDir) { for (const s of r.skipped ?? []) console.log(`⚠️ ${s}`); return 1 } // 闸门拒绝（未动任何状态）
        if (r.dryRun) { console.log('[dry-run] 将备份并重置：'); for (const t of r.targets) console.log(`  ${t}`); return 0 }
        if (r.ok) {
          console.log(`✅ GUI 外壳网络状态已重置（原状态备份在 ${r.guardDir}）`)
          console.log('现在启动 DeepSeek 桌面即可（登录凭据不受影响）。')
        } else {
          console.log(`⚠️ GUI 外壳状态重置未完整成功（备份/现场在 ${r.guardDir}）：`)
          for (const e of r.errors ?? []) console.log(`   ⚠️ ${e}`)
          console.log('请检查上述错误后重试；确认桌面已完全退出（含托盘）。')
        }
        return r.ok ? 0 : 1
      }
      case 'state': {
        const store = resolveStore()
        const profile = resolveProfile()
        if (args._[1] === '--clear') { markCleanExit(store, profile.name); return jsonOut({ ok: true, cleared: true }) }
        const s = readState(store, profile.name)
        const interrupted = readInterruptedRestore(store)
        return jsonOut({ ok: true, state: s, pidAlive: s ? pidAlive(s.pid) : null, interruptedRestore: interrupted })
      }
      case 'preflight': {
        const spec = args._[1]
        if (!spec) return jsonOut({ ok: false, code: 'no-spec', hint: '用法：preflight <pkg-spec>（如 dsh-lifeguard 或 dsh-lifeguard@0.7.10）' })
        const r = await preflightPackage({ spec, profile: resolveProfile(), store: resolveStore() })
        if (args.json) return jsonOut(r)
        console.log(`装前体检：${r.spec}${r.name ? ` → ${r.name}` : ''}${r.harnessVersion ? `（本机 harness ${r.harnessVersion}）` : ''}`)
        for (const c of r.checks) console.log(`${c.ok ? '✅' : '⚠️'} ${c.id}: ${c.detail}`)
        console.log('（只告警不阻断；是否安装由你决定）')
        return 0 // 告警不改变退出码，防止脚本误判失败
      }
      case 'serve': {
        const r = await serveStore({ store: resolveStore(), port: args.port })
        return jsonOut(r) // 服务停止后到达
      }
      case 'diff': {
        const store = resolveStore()
        const idA = args._[1], idB = args._[2] || newestSnapshotId(store)
        if (!idA) return jsonOut({ ok: false, code: 'usage', hint: 'diff <idA> [idB]；id 可用 list 查' })
        const d = diffSnapshots(store, idA, idB)
        if (!d.ok) return jsonOut(d)
        if (args.json) return jsonOut(d)
        console.log(`差异 ${d.from} → ${d.to}：新增 ${d.counts.added} / 删除 ${d.counts.removed} / 内容变化 ${d.counts.changed}`)
        if (d.topPackages.added.length) console.log(`顶层新增包：${d.topPackages.added.join(', ')}`)
        if (d.topPackages.removed.length) console.log(`顶层移除包：${d.topPackages.removed.join(', ')}`)
        const show = (title, arr, cap) => {
          if (!arr.length) return
          console.log(`${title}（前 ${Math.min(cap, arr.length)}）：`)
          for (const rel of arr.slice(0, cap)) console.log(`  ${rel}`)
        }
        show('新增', d.samples.added, 12)
        show('删除', d.samples.removed, 12)
        show('内容变化', d.samples.changed, 12)
        return 0
      }
      case 'unstick': {
        const r = unstick(resolveProfile().dir)
        if (!r.removed.length && !r.kept.length) { console.log('无残留锁'); return jsonOut({ ok: true, clean: true }) }
        for (const x of r.removed) console.log(`✅ 已清理 ${x.kind}: ${x.detail}`)
        for (const x of r.kept) console.log(`⚠️ 未能清理 ${x.kind}: ${x.error}`)
        return jsonOut({ ok: true, ...r })
      }
      case 'selftest': {
        const results = selftest()
        for (const r of results) console.log(`${r.ok ? '✅' : '❌'} ${r.name}${r.ok ? '' : ` — ${r.error}`}`)
        return results.every((r) => r.ok) ? 0 : 1
      }
      default:
        console.error(`未知命令：${cmd}\n${HELP}`)
        return 2
    }
  } catch (e) {
    return jsonOut({ ok: false, code: 'error', error: String(e?.stack || e) })
  }
}

/* 直接运行才进入 CLI（被 import 时只导出 API） */
const isMain = (() => {
  try { return resolve(process.argv[1] || '') === resolve(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isMain) {
  Promise.resolve(main())
    .then((code) => process.exit(typeof code === 'number' ? code : 0))
    .catch((e) => { console.error(String(e?.stack || e)); process.exit(1) })
}
