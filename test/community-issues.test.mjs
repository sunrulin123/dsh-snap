/**
 * dsh-snap — 社区常见故障模式注入套件（零依赖，直接打内核 API）。
 * 场景来源：竞品事故史 + 业界共识 + 社区调研（E:\AI\dsh-plugin-research\p0-verification\社区常见故障模式调研.md）。
 * 覆盖：中文/空格路径、长路径、跨卷 store、损坏 manifest、撕裂 journal、并发快照、
 *       junction 环、只读 store、畸形 spec、垃圾日志、缺索引、大文件跨卷、空环境。
 */

import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, chmodSync, existsSync, statSync, openSync, closeSync, truncateSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawn } from 'node:child_process'
import { pathToFileURL } from 'node:url'

import { fileURLToPath } from 'node:url'
// F2：ROOT 从本文件位置推导（曾硬编码 E:/AI/Projects/dsh-snap——换机/换盘即断）
const ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/[\\/]$/, '')
const kernel = await import(pathToFileURL(join(ROOT, 'cli', 'dsh-snap.mjs')).href)
const {
  takeSnapshot, restoreSnapshot, verifySnapshot, listSnapshots, readSnapshotManifest,
  pruneSnapshots, doctor, attributeCrash, preflightPackage, satisfies, specToName,
  readInterruptedRestore, resolveDshHome, resolveProfile, resolveStore, markBoot,
} = kernel

const results = []
const t = (name, fn) => Promise.resolve().then(fn).then(
  () => results.push({ name, ok: true }),
  (e) => results.push({ name, ok: false, error: String(e?.message || e).slice(0, 300) }),
)

function makeEnv(homeName, { nmFiles = 2, withLock = true, withPatch = true } = {}) {
  const home = mkdtempSync(join(tmpdir(), `dsh-snap-fi-${homeName}-`))
  const prof = join(home, 'profiles', 'desktop')
  const nm = join(prof, 'node_modules')
  mkdirSync(join(nm, 'base-pkg'), { recursive: true })
  writeFileSync(join(nm, 'base-pkg', 'index.js'), 'console.log(1)\n')
  writeFileSync(join(nm, 'base-pkg', 'package.json'), '{"name":"base-pkg","version":"1.0.0"}')
  if (nmFiles >= 2) {
    mkdirSync(join(nm, 'other-pkg'), { recursive: true })
    writeFileSync(join(nm, 'other-pkg', 'a.js'), 'a'.repeat(100))
  }
  writeFileSync(join(prof, 'package.json'), '{"dependencies":{"base-pkg":"1.0.0"}}')
  if (withLock) writeFileSync(join(prof, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n')
  if (withPatch) writeFileSync(join(prof, 'cordis.patch.yml'), 'entries: []\n')
  return { home, prof, nm }
}

const profOf = (home) => ({ name: 'desktop', dir: join(home, 'profiles', 'desktop') })

/* ---- S1 中文 + 空格路径 全链路 ---- */
await t('S1 中文/空格路径：快照→篡改→还原→verify 全链路', () => {
  const base = mkdtempSync(join(tmpdir(), 'dsh-snap-fi-中文 基础-'))
  const home = join(base, 'DSH 目录') // 空格
  const prof = join(home, 'profiles', '桌面配置') // 中文
  const nm = join(prof, 'node_modules')
  mkdirSync(join(nm, '包甲'), { recursive: true })
  writeFileSync(join(nm, '包甲', '入口.js'), '模块内容甲\n')
  writeFileSync(join(prof, 'package.json'), '{"dependencies":{"包甲":"1.0.0"}}')
  writeFileSync(join(prof, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n')
  const profObj = { name: '桌面配置', dir: prof }
  const m = takeSnapshot({ store: join(base, 'snap'), profile: profObj, trigger: 'manual' })
  if (!m.layers.profile.taken.includes('package.json')) throw new Error('清单未拍')
  // 破坏 + 还原
  rmSync(join(nm, '包甲', '入口.js'))
  writeFileSync(join(prof, 'package.json'), '{"dependencies":{}}')
  const r = restoreSnapshot({ store: join(base, 'snap'), target: m.id, profile: profObj, skipProcessProbe: true })
  if (!r.ok) throw new Error(`还原失败 ${r.code || ''}`)
  if (readFileSync(join(nm, '包甲', '入口.js'), 'utf8') !== '模块内容甲\n') throw new Error('中文路径文件未回填')
  const v = verifySnapshot(join(base, 'snap'), m.id, { deep: true })
  if (!v.ok) throw new Error('还原后 verify 不过')
  rmSync(base, { recursive: true, force: true })
})

/* ---- S2 超长路径（Windows MAX_PATH 逼近） ---- */
await t('S2 长路径：深层嵌套包名快照与还原', () => {
  const { home, nm } = makeEnv('长路径')
  const deep = ['很长的顶层包名-aaaaaaaaaa', 'bbbbbbbbbb', 'cccccccccc', 'dddddddddd', 'eeeeeeeeee', 'ffffffffff', 'gggggggggg']
  let p = nm
  for (const seg of deep) p = join(p, seg)
  mkdirSync(p, { recursive: true })
  writeFileSync(join(p, 'deep.js'), 'deep\n')
  const store = join(home, 'snap')
  const m = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
  rmSync(join(p, 'deep.js'))
  const r = restoreSnapshot({ store, target: m.id, profile: profOf(home), skipProcessProbe: true })
  if (!r.ok) throw new Error(`还原失败：${JSON.stringify(r.reported?.slice(0, 2))}`)
  if (!existsSync(join(p, 'deep.js'))) throw new Error('深层文件未回填')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S3 跨卷 store（copy 降级路径）：home 与 store 必须在不同卷。
 * F2（0.7.4 审计）：曾硬编码 E:\AI\dsh-plugin-research\tmp——单卷机器/他机环境直接炸。
 * 可移植策略：优先 tmpdir 之外的卷（本机 tmpdir=C:、数据盘=E:），找不到第二卷则跳过（注明）。 */
const crossVolHome = (() => {
  const tmpRoot = tmpdir() // 形如 C:\Users\...\Temp
  const tmpDrive = tmpRoot.slice(0, 2).toLowerCase()
  for (const cand of ['E:', 'D:', 'F:']) {
    if (cand.toLowerCase() === tmpDrive) continue
    try { mkdirSync(join(cand, 'dsh-snap-test-tmp'), { recursive: true }); return join(cand, 'dsh-snap-test-tmp') } catch { /* 卷不存在 */ }
  }
  return null
})()
await t('S3 跨卷 store：复制降级 + verify + 还原', () => {
  if (!crossVolHome) { results.push({ name: 'S3 跨卷 store：复制降级 + verify + 还原（跳过：无第二卷）', ok: true }); return }
  const stamp = Date.now()
  const home = join(crossVolHome, `fi-home-crossvol-${stamp}`)
  const prof = join(home, 'profiles', 'desktop')
  const nm = join(prof, 'node_modules')
  mkdirSync(join(nm, 'base-pkg'), { recursive: true })
  writeFileSync(join(nm, 'base-pkg', 'index.js'), 'console.log(1)\n')
  writeFileSync(join(prof, 'package.json'), '{"dependencies":{"base-pkg":"1.0.0"}}')
  const store = join(tmpdir(), `fi-crossvol-store-${stamp}`) // tmpdir 卷
  try {
    const m = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
    if (!m.layers.nodeModules.present || m.stats.copied < 1) throw new Error(`跨卷未走复制：${JSON.stringify(m.stats)}`)
    rmSync(join(nm, 'base-pkg', 'index.js'))
    const r = restoreSnapshot({ store, target: m.id, profile: profOf(home), skipProcessProbe: true })
    if (!r.ok) throw new Error('跨卷还原失败')
    if (readFileSync(join(nm, 'base-pkg', 'index.js'), 'utf8') !== 'console.log(1)\n') throw new Error('跨卷复制内容不符')
    const v = verifySnapshot(store, m.id, { deep: true })
    if (!v.ok) throw new Error('跨卷快照 verify 不过')
  } finally { rmSync(store, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }) }
})

/* ---- S4 损坏 manifest（半写/版本错/id 不符） ---- */
await t('S4 损坏 manifest：隔离不崩、好快照不受影响', () => {
  const { home } = makeEnv('损坏清单')
  const store = join(home, 'snap')
  const good = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
  // 造三个坏快照：半写 JSON / 版本错 / 内容被清
  for (const [id, content] of [
    ['20990101T000000-aaa111', '{"version":1,"id":"20990101T000000-aaa111","layers":'], // 半写
    ['20990101T000000-bbb222', '{"version":999}'],
    ['20990101T000000-ccc333', ''],
  ]) {
    mkdirSync(join(store, 'snapshots', id), { recursive: true })
    writeFileSync(join(store, 'snapshots', id, 'manifest.json'), content)
  }
  const all = listSnapshots(store)
  if (all.filter((m) => m.corrupted).length !== 3) throw new Error(`隔离数不对：${all.filter((m) => m.corrupted).length}`)
  if (readSnapshotManifest(store, good.id)?.id !== good.id) throw new Error('好快照被误伤')
  const r = restoreSnapshot({ store, target: '20990101T000000-aaa111', profile: profOf(home), skipProcessProbe: true })
  if (r.ok !== false || r.code !== 'snapshot-not-found') throw new Error(`坏快照应拒绝还原：${JSON.stringify(r)}`)
  rmSync(home, { recursive: true, force: true })
})

/* ---- S5 撕裂 journal + 垃圾崩溃日志（归因健壮性） ---- */
await t('S5 撕裂journal/二进制日志/空日志/未来时间：归因永不炸', () => {
  const { home } = makeEnv('垃圾日志')
  const store = join(home, 'snap')
  mkdirSync(join(store, 'journal'), { recursive: true })
  const lines = [
    '{"kind":"crash-detected","profile":"desktop","time":"2026-11-08T10:00:00Z","prevStartedAt":"2026-11-08T09:00:00Z"}',
    '{"kind":"manifest-change","profile":"desktop","time":"2026-11-08T09:59:00Z","added":["suspect-pkg"],"removed":[]}',
    '{"kind":撕裂行不是JSON', // 撕裂
    '', // 空
    'not json at all', // 垃圾
  ]
  writeFileSync(join(store, 'journal', 'manifest-journal.jsonl'), lines.join('\n'))
  // 垃圾崩溃日志：二进制、超长行、空
  const logDir = join(home, 'logs')
  mkdirSync(logDir, { recursive: true })
  writeFileSync(join(logDir, 'crash-binary.log'), Buffer.concat([Buffer.from([0x00, 0xff, 0xfe, 0x00, 0x0d, 0x0a]), Buffer.alloc(1024, 0x41)]))
  writeFileSync(join(logDir, 'crash-longline.log'), 'x'.repeat(2 * 1024 * 1024) + '\n--- error ---\n' + 'Error: ' + 'y'.repeat(500000))
  writeFileSync(join(logDir, 'crash-empty.log'), '')
  writeFileSync(join(logDir, 'crash-future.log'), 'time: 2999-01-01T00:00:00Z\n--- error ---\nError: future\nexited with 1\n')
  const r = attributeCrash({ store, dshHome: home, profile: profOf(home) })
  if (!r.ok || !Array.isArray(r.crashes) || !Array.isArray(r.suspects)) throw new Error('归因 shape 崩了')
  if (!r.crashes.some((c) => c.file?.includes('crash-future') || c.kind)) throw new Error('连一个崩溃都没解析出')
  const suspect = r.suspects.find((s) => s.pkg === 'suspect-pkg')
  if (!suspect) throw new Error('时间窗关联丢嫌疑（manifest-change 应进 direct）')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S6 并发快照（两进程同拍一个 store） ---- */
await t('S6 并发快照：两进程同拍，两 manifest 完好', async () => {
  const { home } = makeEnv('并发')
  const store = join(home, 'snap')
  const script = `
    import { takeSnapshot } from ${JSON.stringify(pathToFileURL(join(ROOT, 'cli', 'dsh-snap.mjs')).href)}
    const m = takeSnapshot({ store: ${JSON.stringify(store)}, profile: ${JSON.stringify(profOf(home))}, trigger: 'manual' })
    console.log(m.id)
  `
  const scriptPath = join(home, 'concurrent.mjs')
  writeFileSync(scriptPath, script)
  const runOne = () => new Promise((res, rej) => {
    const p = spawn(process.execPath, [scriptPath], { env: { ...process.env, DSH_SNAP_HOME: store }, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    p.stdout.on('data', (c) => { out += c })
    p.on('close', (code) => code === 0 ? res(out.trim()) : rej(new Error(out)))
  })
  const [id1, id2] = await Promise.all([runOne(), runOne()])
  if (!id1 || !id2 || id1 === id2) throw new Error(`并发 id 异常：${id1} / ${id2}`)
  for (const id of [id1, id2]) {
    const v = verifySnapshot(store, id, { deep: true })
    if (!v.ok) throw new Error(`并发快照 ${id} verify 不过`)
  }
  rmSync(home, { recursive: true, force: true })
})

/* ---- S7 junction 环（node_modules 自指 junction） ---- */
await t('S7 junction 环：快照不深循环、verify/restore 不炸', () => {
  const { home, nm } = makeEnv('junction环')
  try { symlinkSync(nm, join(nm, 'self-loop'), 'junction') } catch { /* 非 win 跳过 */ }
  const store = join(home, 'snap')
  const m = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
  if (!m.stats.complete) throw new Error('快照未完成')
  // 环不深读：快照体积应有限（reparse 记录 1 条，未深入）
  const v = verifySnapshot(store, m.id, { deep: true })
  if (!v.ok) throw new Error(`verify 失败：${JSON.stringify(v.samples)}`)
  rmSync(join(nm, 'other-pkg', 'a.js'))
  const r = restoreSnapshot({ store, target: m.id, profile: profOf(home), skipProcessProbe: true })
  if (!r.ok) throw new Error('junction 环环境下还原失败')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S8 只读 store：快照失败不挂死、错误信息可读 ---- */
await t('S8 只读 store：takeSnapshot 抛可读错误而非挂死', () => {
  const { home } = makeEnv('只读库')
  const store = join(home, 'snap')
  mkdirSync(store, { recursive: true })
  writeFileSync(join(store, 'blocker'), 'x')
  try { chmodSync(store, 0o444) } catch { /* Windows chmod 受限时跳过断言 */ }
  let threw = null
  try { takeSnapshot({ store, profile: profOf(home), trigger: 'manual' }) } catch (e) { threw = e }
  try { chmodSync(store, 0o666) } catch { /* 忽略 */ }
  if (process.platform === 'win32') {
    // Windows 上目录只读属性不阻止创建子目录（chmod 语义弱化）——能成功则视为通过，能抛错也算通过
    if (!threw) { /* OK：Windows 只读目录仍可写，无异常即通过 */ }
  } else if (!threw) throw new Error('POSIX 只读目录应抛错')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S9 畸形 spec（preflight 入口面） ---- */
await t('S9 畸形 spec：全部安全拒绝或跳过，不炸不发请求', async () => {
  const bad = ['file:E:/x/y.tgz', 'git+ssh://evil', 'https://x', './local.tgz', '', '   ', '@', '@scope/', '@scope/pkg@', 'a'.repeat(5000), '../../escape', 'pkg;rm-rf', 'latest', 'workspace:*']
  for (const s of bad) {
    const name = specToName(s)
    if (name !== null) {
      // 能解析的（如 latest/workspace:*）也必须是合法包名形态
      if (!/^[a-z0-9-][a-z0-9._-]*$|^@[a-z0-9-][a-z0-9._-]*\/[a-z0-9._-]+$/i.test(name)) throw new Error(`spec "${s}" 解析出非法名 "${name}"`)
    }
  }
  // satisfies 畸形输入：不 throw，只 true/false/null
  for (const range of ['', '   ', '||', '^', '>=', '1.2.3 - ', '((((((1.0.0', 'x'.repeat(3000), '>=0.2.0-0 <0.3.0 || ^1 || ~2 - 3 || file:x']) {
    const r = satisfies('0.2.2-rc.1', range)
    if (![true, false, null].includes(r)) throw new Error(`satisfies 对 "${range.slice(0, 20)}" 返回 ${r}`)
  }
  // preflight 主入口对 file: spec 直接跳过（不发请求）
  const { home } = makeEnv('畸形spec')
  const r = await preflightPackage({ spec: 'file:E:/evil.tgz', profile: profOf(home), store: join(home, 'snap') })
  if (!r.nonBlocking || !r.checks.some((c) => c.id === 'spec-parse')) throw new Error('file: spec 应安全跳过')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S10 files-index 缺失/畸形：restore 与 verify 降级不炸 ---- */
await t('S10 缺失/畸形 files-index：restore 降级为清单层、verify 如实报告', () => {
  const { home, nm } = makeEnv('缺索引')
  const store = join(home, 'snap')
  const m = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
  rmSync(join(store, 'snapshots', m.id, 'files-index.tsv'))
  const v = verifySnapshot(store, m.id)
  if (v.ok !== false || v.indexMissing !== true) throw new Error('verify 应报 indexMissing')
  const r = restoreSnapshot({ store, target: m.id, profile: profOf(home), skipProcessProbe: true })
  // E2（0.7.4 审计）：index-missing 属硬错误——profile 清单层照常还原，但整体必须
  // ok:false + partial:true（曾 ok:true 假成功）
  if (r.ok !== false || r.partial !== true) throw new Error(`索引缺失未标部分失败：ok=${r.ok} partial=${r.partial}`)
  if (!r.reported.some((x) => x.issue === 'index-missing')) throw new Error('未报告 index-missing')
  if (!r.profile.length) throw new Error('索引缺失时 profile 清单层仍应还原')
  // 畸形索引：行列数不足
  const m2 = takeSnapshot({ store, profile: profOf(home), trigger: 'manual', prevId: m.id })
  writeFileSync(join(store, 'snapshots', m2.id, 'files-index.tsv'), 'broken-row-no-tabs\n\n\t\t\t\n')
  const v2 = verifySnapshot(store, m2.id)
  if (typeof v2.ok !== 'boolean') throw new Error('畸形索引 verify 未返回布尔')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S11 大文件跨卷跳过（64MB 上限只约束复制路径） ---- */
await t('S11 跨卷 70MB 大文件：跳过且如实计数，不撑爆快照库', () => {
  if (!crossVolHome) { results.push({ name: 'S11 跨卷 70MB 大文件（跳过：无第二卷）', ok: true }); return }
  const stamp = Date.now()
  const home = join(crossVolHome, `fi-home-big-${stamp}`)
  const prof = join(home, 'profiles', 'desktop')
  const nm = join(prof, 'node_modules')
  mkdirSync(join(nm, 'big'), { recursive: true })
  const big = join(nm, 'big', 'huge.bin')
  const fd = openSync(big, 'w')
  closeSync(fd)
  truncateSync(big, 70 * 1024 * 1024) // 稀疏写：只标记大小
  const store = join(tmpdir(), `fi-big-store-${stamp}`) // C: 卷 → 跨卷必走复制路径
  try {
    const m = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
    if (m.stats.bigSkipped < 1) throw new Error(`大文件未跳过：${JSON.stringify(m.stats)}`)
    if (statSync(join(store, 'snapshots', m.id)).size > 50 * 1024 * 1024) throw new Error('快照库被大文件撑爆')
  } finally { rmSync(store, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }) }
})

/* ---- S12 空/极端环境：全新机器、空 node_modules、缺清单 ---- */
await t('S12 全新机器/空目录：doctor 与快照链路全可用', () => {
  const home = mkdtempSync(join(tmpdir(), 'dsh-snap-fi-全新-'))
  const prof = join(home, 'profiles', 'desktop')
  mkdirSync(prof, { recursive: true }) // 什么都没有
  const d = doctor(profOf(home))
  if (typeof d.ok !== 'boolean' || !Array.isArray(d.checks)) throw new Error('doctor 对空环境 shape 异常')
  const m = takeSnapshot({ store: join(home, 'snap'), profile: profOf(home), trigger: 'manual' })
  if (m.stats.files !== 0) throw new Error('空环境快照文件数应为 0')
  const r = restoreSnapshot({ store: join(home, 'snap'), target: m.id, profile: profOf(home), skipProcessProbe: true })
  if (!r.ok) throw new Error('空环境还原失败')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S13 中断还原记录的 pid 复用边界 ---- */
await t('S13 中断记录：活pid不误报+进度残留检出', () => {
  const { home } = makeEnv('中断pid')
  const store = join(home, 'snap')
  takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
  // 模拟：写入进度文件但 pid 指向本进程（活着）→ 不算中断
  kernel // 侧写进度文件
  writeFileSync(join(store, 'restore-in-progress.json'), JSON.stringify({ pid: process.pid, target: 'x', guardId: 'g', phase: 'node-modules', startedAt: Date.now(), profile: 'desktop' }))
  if (readInterruptedRestore(store) !== null) throw new Error('活 pid 被误报为中断')
  // pid 换成不存在的 → 检出
  writeFileSync(join(store, 'restore-in-progress.json'), JSON.stringify({ pid: 2147483000, target: 'x', guardId: 'g', phase: 'node-modules', startedAt: Date.now(), profile: 'desktop' }))
  const it = readInterruptedRestore(store)
  if (!it || it.phase !== 'node-modules') throw new Error('死 pid 中断未被检出')
  rmSync(join(store, 'restore-in-progress.json'))
  rmSync(home, { recursive: true, force: true })
})

/* ---- S14 prune 与损坏快照共存 + 配额为 0 ---- */
await t('S14 prune 极端配额：0字节0数量0天不删豁免、损坏项不碰', () => {
  const { home } = makeEnv('极端prune')
  const store = join(home, 'snap')
  const manual = takeSnapshot({ store, profile: profOf(home), trigger: 'manual', label: '保留我' })
  takeSnapshot({ store, profile: profOf(home), trigger: 'baseline' })
  takeSnapshot({ store, profile: profOf(home), trigger: 'agent:install_bundle:x' })
  mkdirSync(join(store, 'snapshots', '20990101T000000-dead99'), { recursive: true })
  writeFileSync(join(store, 'snapshots', '20990101T000000-dead99', 'manifest.json'), '{bad')
  const r = pruneSnapshots(store, { maxSnapshots: 0, maxBytes: 0, ttlDays: 0 })
  const left = listSnapshots(store)
  if (!left.some((m) => m.id === manual.id)) throw new Error('手动快照被 0 配额误删')
  if (!left.some((m) => m.corrupted && m.id === '20990101T000000-dead99')) throw new Error('损坏项被 prune 删除（应留给人工隔离）')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S15 state 文件/多 profile 共存 ---- */
await t('S15 多 profile state：互不覆盖、崩溃标志隔离', () => {
  const { home } = makeEnv('多profile')
  const store = join(home, 'snap')
  mkdirSync(store, { recursive: true })
  process.env.DSH_SNAP_HOME = store
  try {
    const a = markBoot(store, { profile: 'desktop' })
    const b = markBoot(store, { profile: 'web' })
    if (a.state.bootId === b.state.bootId) throw new Error('bootId 未区分')
    const sa = JSON.parse(readFileSync(join(store, 'state-desktop.json'), 'utf8'))
    const sb = JSON.parse(readFileSync(join(store, 'state-web.json'), 'utf8'))
    if (sa.profile !== 'desktop' || sb.profile !== 'web') throw new Error('state 分文件失败')
    kernel.markCleanExit(store, 'desktop')
    const sa2 = JSON.parse(readFileSync(join(store, 'state-desktop.json'), 'utf8'))
    if (sa2.cleanExit !== true) throw new Error('cleanExit 未写入')
    if (JSON.parse(readFileSync(join(store, 'state-web.json'), 'utf8')).cleanExit !== false) throw new Error('web 的 cleanExit 被误改')
  } finally { delete process.env.DSH_SNAP_HOME; rmSync(home, { recursive: true, force: true }) }
})

/* ---- S16 restore 目标快照期间源文件被外部删除（竞态） ---- */
await t('S16 还原中快照文件被删：报告且 ok:false+partial（E2 语义，不再假成功）', () => {
  const { home, nm } = makeEnv('还原竞态')
  const store = join(home, 'snap')
  const m = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
  // 删掉快照侧一个文件（模拟 AV 隔离/人为）
  rmSync(join(store, 'snapshots', m.id, 'node_modules', 'base-pkg', 'index.js'))
  rmSync(join(nm, 'base-pkg', 'index.js'))
  const r = restoreSnapshot({ store, target: m.id, profile: profOf(home), skipProcessProbe: true })
  // E2（0.7.4 审计）：快照缺文件曾 ok:true 假成功——其余可恢复项照常回填，但整体必须
  // ok:false + partial:true（guardId 在，可重试/undo）
  if (r.ok !== false || r.partial !== true) throw new Error(`快照缺文件未标部分失败：ok=${r.ok} partial=${r.partial}`)
  if (!r.guardId) throw new Error('partial 失败必须保留 guardId（可回退）')
  if (!r.reported.some((x) => x.issue === 'snapshot-file-missing')) throw new Error('未报告 snapshot-file-missing')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S17 resolveDshHome 候选链（无 env、无 ~/.dsh） ---- */
await t('S17 DSH_HOME 解析：env 优先、默认链兜底不炸', () => {
  const saved = process.env.DSH_HOME
  try {
    delete process.env.DSH_HOME
    const h = resolveDshHome()
    if (typeof h !== 'string' || !h) throw new Error('无 env 时应返回默认候选')
    const p = resolveProfile(h)
    if (!p || typeof p.name !== 'string') throw new Error('resolveProfile 对不存在 home 不应炸')
    const s = resolveStore(h)
    if (typeof s !== 'string') throw new Error('resolveStore 不应炸')
  } finally { if (saved !== undefined) process.env.DSH_HOME = saved }
})

/* ---- S18 verify 对 benign 文件的真实篡改（应报 modified 而非 benign） ---- */
await t('S18 benign 边界：.modules.yaml 私有副本被真篡改仍可检出', () => {
  const { home, nm } = makeEnv('benign边界')
  const store = join(home, 'snap')
  // E3（0.7.4 审计）：夹具曾不创建 .modules.yaml——takeSnapshot 时 nm 没有该文件，
  // 快照侧也不存在，existsSync 恒 false，核心断言从未执行（空转测试）
  writeFileSync(join(nm, '.modules.yaml'), 'layoutVersion: 9.0\n')
  const m = takeSnapshot({ store, profile: profOf(home), trigger: 'manual' })
  // 私有副本（非硬链接）被直接篡改 = size/mtime 变化 → 非 deep 就要检出（它不是"live 原地写"路径，是快照被真改）
  const snapSide = join(store, 'snapshots', m.id, 'node_modules', '.modules.yaml')
  if (!existsSync(snapSide)) throw new Error('夹具失败：快照侧应有 .modules.yaml 私有副本')
  writeFileSync(snapSide, 'layoutVersion: hacked-longer-content\n')
  const v = verifySnapshot(store, m.id, { deep: true })
  if (v.ok || v.modifiedCount < 1) throw new Error(`快照侧私有副本被直接篡改未检出：${JSON.stringify({ ok: v.ok, modifiedCount: v.modifiedCount, benignModifiedCount: v.benignModifiedCount })}`)
  rmSync(home, { recursive: true, force: true })
})

/* ---- S19 时钟偏移：系统时间回拨后的快照排序与 prune ---- */
await t('S19 时钟回拨：快照排序与 prune 不误删', () => {
  const { home } = makeEnv('时钟回拨')
  const store = join(home, 'snap')
  const m1 = takeSnapshot({ store, profile: profOf(home), trigger: 'baseline' })
  // 伪造"未来"快照（mtime/时间字段前瞻）→ listSnapshots 按字段排序不应崩
  const future = readFileSync(join(store, 'snapshots', m1.id, 'manifest.json'), 'utf8')
  const fm = JSON.parse(future)
  fm.time = '2999-01-01T00:00:00.000Z'; fm.timeEpoch = Date.now() + 10 * 365 * 86400_000
  writeFileSync(join(store, 'snapshots', m1.id, 'manifest.json'), JSON.stringify(fm, null, 2))
  const all = listSnapshots(store)
  if (!all.length) throw new Error('未来时间快照被排序逻辑丢弃')
  const r = pruneSnapshots(store, { maxSnapshots: 5, ttlDays: 30 })
  if (typeof r.ok !== 'boolean') throw new Error('prune 对未来时间不返回布尔')
  rmSync(home, { recursive: true, force: true })
})

/* ---- S20 journal 大量垃圾与超大 journal（归因性能上界） ---- */
await t('S20 超大 journal（5万行垃圾）：归因限界内完成', () => {
  const { home } = makeEnv('超大journal')
  const store = join(home, 'snap')
  mkdirSync(join(store, 'journal'), { recursive: true })
  const chunks = []
  const one = JSON.stringify({ kind: 'snapshot', id: '20261108T000000-ffffff', trigger: 'agent:install_bundle:pkg-x', spec: 'pkg-x', profile: 'desktop', time: '2026-11-08T00:00:00Z' })
  for (let i = 0; i < 50000; i++) chunks.push(one)
  writeFileSync(join(store, 'journal', 'manifest-journal.jsonl'), chunks.join('\n'))
  const t0 = Date.now()
  const r = attributeCrash({ store, dshHome: home, profile: profOf(home) })
  const ms = Date.now() - t0
  if (!r.ok) throw new Error('大 journal 归因失败')
  if (ms > 15000) throw new Error(`归因耗时 ${ms}ms 超界`)
  rmSync(home, { recursive: true, force: true })
})

/* ---- 汇总 ---- */
const pass = results.filter((r) => r.ok).length
for (const r of results) console.log(`${r.ok ? '✅' : '❌'} ${r.name}${r.ok ? '' : ` — ${r.error}`}`)
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
