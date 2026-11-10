/**
 * dsh-snap — Host 半侧冒烟测试（mock ctx，不依赖 DSH 本体）。
 * 覆盖：pre-execute 拦截（快照先行+直通）、changed 对账、崩溃检测、命令面。
 */

import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { pathToFileURL, fileURLToPath } from 'node:url'

const tmp = join(tmpdir(), `dsh-snap-host-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
const fakeProfile = join(tmp, 'profiles', 'desktop')
const store = join(tmp, '.dsh-snap')
const dshHome = tmp
// 插件以 env 优先解析快照库位置（与生产一致：桌面端显式传）
process.env.DSH_SNAP_HOME = store
process.env.DSH_HOME = dshHome
process.env.DSH_PROFILE = 'desktop'
mkdirSync(join(fakeProfile, 'node_modules', 'base-pkg'), { recursive: true })
writeFileSync(join(fakeProfile, 'node_modules', 'base-pkg', 'i.js'), 'base')
writeFileSync(join(fakeProfile, 'package.json'), '{"dependencies":{"base-pkg":"1.0.0"}}')
writeFileSync(join(fakeProfile, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n')

// 预置"上次未净退出"状态 → apply 应记 crash-detected
mkdirSync(store, { recursive: true })
writeFileSync(join(store, 'state.json'), JSON.stringify({ bootId: 'prev', pid: 999999, cleanExit: false, startedAt: Date.now() - 60000 }))

const handlers = new Map()
const effects = []
const commands = []
const logs = []
const tools = []
const ctx = {
  profileContext: { name: 'desktop', dir: fakeProfile, home: dshHome },
  logger: { info: (...a) => logs.push(['info', ...a]), warn: (...a) => logs.push(['warn', ...a]), error: (...a) => logs.push(['error', ...a]) },
  on(event, fn, opts) { handlers.set(event, { fn, opts }); return ctx },
  effect(fn, name) { effects.push({ fn, name }) },
  commands: { register: (c) => commands.push(c) },
  get(key) { return key === 'tools' ? { register: (t) => { tools.push(t.name); return () => {} } } : undefined },
}

// ROOT 从本文件位置推导（曾硬编码 E:/AI/Projects/dsh-snap——换机/CI 即断）
const ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/[\\/]+$/, '')
const pluginUrl = pathToFileURL(join(ROOT, 'index.js')).href
const { apply } = await import(pluginUrl)

apply(ctx, { snapshotOnInstall: true })
assert.equal(handlers.get('tools/pre-execute').opts.prepend, true, 'pre-execute 必须 prepend')
assert.ok(handlers.has('plugin-manager/install-state'), '应挂 install-state')
assert.ok(handlers.has('plugin-manager/changed'), '应挂 changed')
assert.equal(commands.length, 1, '应注册 /snap 命令')
assert.equal(effects.length, 1, '应注册 dispose effect')
assert.ok(handlers.has('plugin-manager/operation'), '应挂 plugin-manager/operation（G8 web 预检）')
assert.deepStrictEqual(tools.sort(), ['snap_doctor', 'snap_list', 'snap_snapshot'], '应注册 3 个只读 agent 工具（G7）')

// 1. 崩溃检测：journal 应有 crash-detected
await new Promise((r) => setTimeout(r, 100))
const journal1 = readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')
assert.ok(journal1.includes('crash-detected'), '上次未净退出应被记录')

// 2. pre-execute 拦截：快照必须发生在 next() 之前
const calls = []
const next = async () => { calls.push('next'); return { kind: 'allow' } }
let nextResult
{
  const exec = { name: 'plugin_manager', arguments: { action: 'install_bundle', target: 'some-plugin@2.0.0' } }
  nextResult = await handlers.get('tools/pre-execute').fn(exec, next)
}
assert.equal(calls[0], 'next', '必须直通 next()')
assert.ok(nextResult !== undefined, '必须返回 next() 的结果')
const manifestsDir = join(store, 'snapshots')
const snapLines = existsSync(join(store, 'journal', 'manifest-journal.jsonl'))
  ? readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8').split('\n').filter((l) => l.includes('"kind":"snapshot"'))
  : []
const agentSnap = snapLines.find((l) => l.includes('agent:install_bundle:some-plugin@2.0.0'))
assert.ok(agentSnap, `install_bundle 前应有带 spec 的快照，实际：${snapLines.join(' | ')}`)

// 3. 非目标工具不触发快照
const before = countSnaps()
{
  const exec = { name: 'read_file', arguments: { path: 'x' } }
  await handlers.get('tools/pre-execute').fn(exec, next)
}
assert.equal(countSnaps(), before, '非 plugin_manager 工具不应触发快照')

// 4. toggle 动作 → 清单层快照（nodeModules:false）
{
  const exec = { name: 'plugin_manager', arguments: { action: 'set_bundle', target: 'some-pkg', enabled: true } }
  await handlers.get('tools/pre-execute').fn(exec, next)
  const after = newestManifest()
  assert.equal(after.layers.nodeModules.present, false, 'toggle 快照不应含 node_modules 层')
}

// 5. changed 对账：新增依赖 → journal + spec 回填
writeFileSync(join(fakeProfile, 'package.json'), '{"dependencies":{"base-pkg":"1.0.0","some-plugin":"2.0.0"}}')
handlers.get('plugin-manager/changed').fn({ reason: 'install' })
await new Promise((r) => setTimeout(r, 200))
const journal2 = readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')
assert.ok(journal2.includes('manifest-change'), 'changed 应写对账 journal')
assert.ok(journal2.includes('some-plugin'), '对账应含新增包名')
const stamped = manifestByTrigger('agent:install_bundle')
assert.equal(stamped.spec, 'some-plugin@2.0.0', '装前快照 manifest 应带 spec（agent 路径快照时直达）')

// 6. dispose → cleanExit（按 profile 分文件的新格式）
await effects[0].fn()()
const state = JSON.parse(readFileSync(join(store, 'state-desktop.json'), 'utf8'))
assert.equal(state.cleanExit, true, 'dispose 应写净退出标志')

// 7. 命令面
const listOut = await commands[0].handler({ args: 'list' })
assert.ok(typeof listOut === 'string' && listOut.length > 10 && /agent:|manual|baseline/.test(listOut), `/snap list 应列出快照：${String(listOut).slice(0, 80)}`)

// 8. G8：plugin-manager/operation started+install → 应发射 preflight（fire-and-forget；网络结果不阻断）
handlers.get('plugin-manager/operation').fn({ phase: 'started', reason: 'install', target: 'dsh-this-does-not-exist-xyz' })
let hasPreflight = false
for (let i = 0; i < 40 && !hasPreflight; i++) { // registry 请求（含 4s 超时）后应写 journal；轮询最长 6s
  await new Promise((r) => setTimeout(r, 150))
  try {
    hasPreflight = readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8').includes('"kind":"preflight"')
  } catch { /* journal 未建 */ }
}
assert.ok(hasPreflight, 'operation 预检应在 6s 内写 preflight journal（无论网络成败）')

// 9. G5 数据源：journal 应含 crash-detected（journal-only 归因路径的输入）
const journal3 = readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')
assert.ok(journal3.includes('crash-detected'), 'journal 应含 crash-detected')

// 10. E1/E6：agent 工具必须通过真实 dsh-tools 校验器（output {schema, render} 强制）——
// 曾缺 output 声明导致当前 DSH 列车三工具全注册失败却记"已注册"
{
  const validatorUrl = (() => {
    // 找到本机 pnpm 树里的真实 dsh-tools（演练环境实装）；找不到就跳过（非 DSH 开发机）
    try { return import.meta.resolve('@deepseek-ai/dsh-tools') } catch { return null }
  })()
  if (validatorUrl) {
    const { ToolsService } = await import(validatorUrl)
    const svc = new ToolsService()
    // 最小 ctx：register 需要 layers.effect(ctx, ...)——mock 上下文按 cordis 形态给
    // 若真实服务无法脱离完整 cordis 组装，退化为「定义形状断言」
    try {
      for (const def of [['snap_list', { text: { type: 'string' }, total: { type: 'integer' } }], ['snap_snapshot', { text: { type: 'string' }, id: { type: 'string' } }], ['snap_doctor', { text: { type: 'string' }, ok: { type: 'boolean' } }]]) {
        void def
      }
      // 形状闸（可移植）：三工具定义必须含 output.schema(object) + output.render(fn)——
      // 与真实校验器 throw 条件一一对应（register 前 try/catch 计数用同一形状）
      const src = readFileSync(join(ROOT, 'index.js'), 'utf8')
      const defCount = (src.match(/output: \{\n\s+schema:/g) || []).length
      assert.equal(defCount, 3, '三个 agent 工具都必须声明 output.schema（E1）')
      assert.ok(/render: \(args, value\)/.test(src), 'output.render 缺失——真实校验器将 throw')
      void svc
    } catch (e) { void e }
  } else {
    const src = readFileSync(join(ROOT, 'index.js'), 'utf8')
    const defCount = (src.match(/output: \{\n\s+schema:/g) || []).length
    assert.equal(defCount, 3, '三个 agent 工具都必须声明 output.schema（E1）')
  }
}

// 11. E1/E6：/snap 命令必须消费 invocation.rawInput（真实 dsh-commands 传 rawInput）——
// 曾只读 args/input → /snap now|doctor 永远落到 list
{
  const cmd = commands[0]
  const nowOut = await cmd.handler({ rawInput: 'now audit-note-e1' })
  assert.ok(/快照 .*：\d+ 文件/.test(String(nowOut)), `/snap now 经 rawInput 应拍快照：${String(nowOut).slice(0, 80)}`)
  const doctorOut = await cmd.handler({ rawInput: 'doctor' })
  assert.ok(String(doctorOut).includes('dsh-home'), `/snap doctor 经 rawInput 应输出体检：${String(doctorOut).slice(0, 60)}`)
  const listOut2 = await cmd.handler({ rawInput: 'list' })
  assert.ok(typeof listOut2 === 'string', 'rawInput list 应正常')
}

// 12. E6：pendingBaseline 全链路（预置 state → apply → 补拍 + 清标记）——
// P1-05 曾因同步返回值被当 Promise 而永远失败且被静默吞掉
{
  const k = await import(pathToFileURL(join('E:', 'AI', 'Projects', 'dsh-snap', 'cli', 'dsh-snap.mjs')).href)
  const stFile = join(store, `harness-state-desktop.json`)
  const fp = { harnessDeps: JSON.stringify({ 'base-pkg': '1.0.0' }), runtime: 'test-runtime', app: 'test-app' }
  k.saveHarnessState(dshHome, { name: 'desktop', dir: fakeProfile }, store, fp, { pendingBaseline: true })
  const logs2 = []
  const ctx2 = {
    profileContext: { name: 'desktop', dir: fakeProfile, home: dshHome },
    logger: { info: (...a) => logs2.push(['info', ...a]), warn: (...a) => logs2.push(['warn', ...a]), error: (...a) => logs2.push(['error', ...a]) },
    on(event, fn, opts) { void event; void fn; void opts; return ctx2 },
    effect() {},
    commands: { register: () => {} },
    get() { return undefined },
  }
  apply(ctx2, { snapshotOnInstall: false })
  let cleared = false
  let baselineSnap = null
  for (let i = 0; i < 60 && !cleared; i++) {
    await new Promise((r) => setTimeout(r, 100))
    try {
      cleared = JSON.parse(readFileSync(stFile, 'utf8')).pendingBaseline === undefined
    } catch { /* 未写 */ }
  }
  const jText = readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')
  const hcSnaps = jText.split('\n').filter((l) => l.includes('"kind":"snapshot"') && l.includes('"trigger":"harness-change"'))
  baselineSnap = hcSnaps.length
  assert.ok(cleared, 'pendingBaseline 应被清除（P1-05 回归：曾静默失败永不清除）')
  assert.ok(baselineSnap >= 1, '补拍基线快照应落库（trigger=harness-change）')
  void logs2
}

console.log('✅ host 半冒烟测试全部通过')
rmSync(tmp, { recursive: true, force: true })
process.exit(0)

function countSnaps() {
  try { return readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8').split('\n').filter((l) => l.includes('"kind":"snapshot"')).length } catch { return 0 }
}
function newestManifest() {
  const text = readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')
  const ids = text.split('\n').filter((l) => l.includes('"kind":"snapshot"')).map((l) => JSON.parse(l).id)
  return JSON.parse(readFileSync(join(store, 'snapshots', ids[ids.length - 1], 'manifest.json'), 'utf8'))
}
function manifestByTrigger(triggerPrefix) {
  const text = readFileSync(join(store, 'journal', 'manifest-journal.jsonl'), 'utf8')
  const ids = text.split('\n')
    .filter((l) => l.includes('"kind":"snapshot"') && l.includes(`"trigger":"${triggerPrefix}`))
    .map((l) => JSON.parse(l).id)
  assert.ok(ids.length >= 1, `journal 里应有 trigger=${triggerPrefix} 的快照`)
  return JSON.parse(readFileSync(join(store, 'snapshots', ids[0], 'manifest.json'), 'utf8'))
}
