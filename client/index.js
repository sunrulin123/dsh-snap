/**
 * dsh-snap — Web 半侧（client face）。
 *
 * 设置页 → 插件 → dsh-snap 标签页：
 *   · 崩溃横幅（上次未净退出提示）
 *   · 快照时间线（时间 / 触发点 / 对象 / 规模 / 耗时）
 *   · 操作：立即快照 · 打开快照库 · 环境体检
 *   · 还原指引（还原刻意不在面板执行——执行体是外部 CLI，DSH 死了也能跑；
 *     面板只负责把命令和 .bat 路径交到用户手里）
 *
 * 无构建步骤：window.__ModuleLoader__.load 客户端包（与 dsh-checkpoint-rewind /
 * dsh-cn-supplement 同形态），React 由壳层 require 提供。
 * 数据经同源 HTTP 路由（宿主半 /dsh-snap/*，带 connection.requestRejection 信任栅栏）。
 */

window.__ModuleLoader__.load({
  id: 'dsh-snap',
  factory: (require) => {
    var react = require('react')
    var createElement = react.createElement
    var Fragment = react.Fragment
    var useState = react.useState
    var useEffect = react.useEffect
    var useCallback = react.useCallback

    var NS = 'dsh-snap'

    /* ---------------- 双语字典（键必须是宿主 LOCALE_IDS：'zh' / 'en'） ---------------- */
    var locales = {
      'zh': {
        tab: '快照与还原',
        title: 'dsh-snap · 装插件搞崩，一键回到装前',
        lead: '每次装/删插件前自动拍快照。还原走外部 CLI（DSH 起不来也能跑）。',
        unclean: '上次运行未净退出（可能是崩溃）。若怀疑插件导致，可还原到最近快照。',
        attrSuspects: '疑似相关插件（时间窗关联，仅供参考）：',
        attrNoSuspects: '崩溃前 24h 内未发现插件变更记录',
        attrShell: '外壳握手失败：',
        attrShellAll: '全部',
        attrShellPart: '部分',
        attrShellOf: '/',
        attrShellTimes: '次崩溃是 GUI 外壳↔宿主本地握手问题，与插件无关。',
        attrShellFix: '修复：完全退出 DSH（含托盘）后运行 `dsh-snap repair-gui`（自动备份并重置外壳网络状态），再启动桌面。官方弹窗的「禁用第三方插件」对此无效，且会砍掉第三方 bundles/patch（可用 repair-profile 恢复）。',
        attrLoop: '崩溃循环：24h 内 ' ,
        attrRestore: '还原到崩溃前快照（先完全退出 DSH，含托盘）：',
        attrTimes: '次',
        colTime: '时间', colTrigger: '触发点', colSpec: '对象', colSize: '规模', colDur: '耗时',
        guard: '还原保护', manual: '手动', baseline: '基线',
        snapNow: '立即快照', openStore: '打开快照库', doctor: '环境体检', verify: '完整性校验',
        verifyOk: '最新快照完整性通过', verifyBad: '快照有异常（见下方详情）',
        verifyMiss: '缺失', verifyMod: '被改', verifyHash: '哈希不符',
        restoreHint: '还原命令（先完全退出 DSH，含托盘）：',
        restoreBat: '或双击快照库里的 restore-last.bat',
        copied: '已复制', copy: '复制',        empty: '快照库为空。装/删一个插件后这里会出现第一条时间线。',
        incomplete: '（不完整）', corrupt: '损坏已隔离：',
        doctorTitle: '环境体检', doctorOk: '全部通过', doctorBad: '有告警项',
        loading: '读取中…', loadError: '读取失败：',
        snapDone: '快照完成', webFiles: '文件',
        stillRunning: '请求超时——操作仍在后台执行中（同步内核无法中断），稍后刷新查看结果，勿重复点击',
        bisect: '二分排查：点时间线任一行 → 回到该点的还原命令（多出的包默认保留并报告，加 --prune-extraneous 才移除）',
        bisectSel: '还原到', bisectAfter: '装后清单（默认保留；--prune-extraneous 才移除）：', bisectNone: '（此点之后没有安装记录）',
        bisectDefault: '当前指向最近快照（restore last）',
        harnessChange: '检测到 harness 环境变化（桌面版更新/运行时更新）',
        harnessChangeHint: '已自动拍更新后基线快照。若更新后出现插件故障，可还原到更早快照对比：',
        harnessUnknown: '依赖指纹不可知',
      },
      'en': {
        tab: 'Snapshots & Restore',
        title: 'dsh-snap · Broke it with a plugin? One click back to pre-install.',
        lead: 'Auto-snapshot before every plugin install/remove. Restore runs outside DSH via CLI.',
        unclean: 'Last run did not exit cleanly (possible crash). If you suspect a plugin, restore to the latest snapshot.',
        attrSuspects: 'Suspected plugins (time-window correlation, informational): ',
        attrNoSuspects: 'No plugin changes found within 24h before the crash',
        attrShell: 'Shell handshake failures: ',
        attrShellAll: 'all ',
        attrShellPart: 'some ',
        attrShellOf: ' of ',
        attrShellTimes: ' crashes are GUI shell ↔ local host handshake issues, unrelated to plugins.',
        attrShellFix: 'Fix: fully quit DSH (tray included), then run `dsh-snap repair-gui` (backs up and resets shell network state), then start the desktop. The official dialog\'s "disable third-party plugins" does not help and truncates third-party bundles/patch (use repair-profile to restore).',
        attrLoop: 'Crash loop: ',
        attrRestore: 'Restore to the pre-crash snapshot (fully quit DSH first): ',
        attrTimes: ' crashes in 24h',
        colTime: 'Time', colTrigger: 'Trigger', colSpec: 'Target', colSize: 'Size', colDur: 'Took',
        guard: 'guard', manual: 'manual', baseline: 'baseline',
        snapNow: 'Snapshot now', openStore: 'Open store', doctor: 'Doctor', verify: 'Verify',
        verifyOk: 'latest snapshot intact', verifyBad: 'snapshot has issues (see details below)',
        verifyMiss: 'missing', verifyMod: 'modified', verifyHash: 'hash mismatch',
        restoreHint: 'Restore command (fully quit DSH first, tray included):',
        restoreBat: 'or double-click restore-last.bat in the store folder',
        copied: 'Copied', copy: 'Copy',
        empty: 'Store is empty. Install/remove a plugin to create the first timeline entry.',
        incomplete: '(incomplete)', corrupt: 'corrupted (quarantined):',
        doctorTitle: 'Doctor', doctorOk: 'all clear', doctorBad: 'warnings',
        loading: 'loading…', loadError: 'failed: ',
        snapDone: 'snapshot done', webFiles: 'files',
        stillRunning: 'Request timed out — the operation is still running in the background (synchronous kernel cannot be interrupted). Refresh later to check results; do not click again.',
        bisect: 'Bisect: click any timeline row to get the restore command for that point (extra packages are kept by default and reported; use --prune-extraneous to remove).',
        bisectSel: 'Restore to', bisectAfter: 'installed after (kept by default; --prune-extraneous removes): ', bisectNone: '(nothing installed after this point)',
        bisectDefault: 'targeting the latest snapshot (restore last)',
        harnessChange: 'Harness environment changed (desktop app / runtime update)',
        harnessChangeHint: 'A post-update baseline snapshot was taken automatically. If plugins misbehave after the update, restore to an earlier snapshot to compare:',
        harnessUnknown: 'dependency fingerprint unavailable',
      },
    }

    /* ---------------- 小工具 ---------------- */
    function pickFetch() {
      if (typeof fetch === 'function') return fetch
      if (typeof window !== 'undefined' && typeof window.fetch === 'function') return window.fetch.bind(window)
      return null
    }
    function fetchJson(route, options) {
      var fetchFn = pickFetch()
      if (fetchFn === null) return Promise.reject(new Error('fetch unavailable'))
      // 12s 超时：宿主半卡死（大快照阻塞等）时按钮不死锁，给用户反馈而非永久 busy
      var opts = Object.assign({ headers: { Accept: 'application/json' }, cache: 'no-store' }, options || {})
      if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) opts.signal = AbortSignal.timeout(12000)
      return fetchFn(route, opts)
        .then(function (res) { return res.json() })
    }
    function fmtBytes(n) {
      if (n === null || n === undefined || !isFinite(n)) return ''
      var u = ['B', 'KB', 'MB', 'GB']; var i = 0; var v = n
      while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
      return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + u[i]
    }
    function fmtTime(iso) {
      try { return new Date(iso).toLocaleString() } catch (e) { return String(iso) }
    }
    function triggerLabel(t, dict) {
      if (!t) return ''
      if (t === 'manual') return dict.manual
      if (t === 'baseline') return dict.baseline
      if (t === 'pre-restore') return dict.guard
      return t
    }
    /** locale 绑定函数 t → triggerLabel 用的迷你字典（曾错传 t 本身致触发点列恒空） */
    function triggerDict(t) {
      return { manual: t('manual'), baseline: t('baseline'), guard: t('guard') }
    }

    /* ---------------- 样式 ---------------- */
    function installStyles() {
      if (typeof document === 'undefined') return
      if (document.getElementById('dsh-snap-styles')) return
      var style = document.createElement('style')
      style.id = 'dsh-snap-styles'
      style.textContent = [
        '.dsh-snap-root{font-size:13px;line-height:1.5;max-width:880px}',
        '.dsh-snap-banner{border:1px solid #d97706;background:rgba(217,119,6,.08);border-radius:8px;padding:10px 12px;margin:0 0 12px}',
        '.dsh-snap-lead{opacity:.75;margin:0 0 14px}',
        '.dsh-snap-actions{display:flex;gap:8px;margin:0 0 14px;flex-wrap:wrap}',
        '.dsh-snap-button{border:1px solid var(--dsh-border,#ccc);border-radius:6px;padding:5px 12px;background:transparent;cursor:pointer;font-size:13px}',
        '.dsh-snap-button:hover{background:rgba(127,127,127,.1)}',
        '.dsh-snap-button[disabled]{opacity:.5;cursor:default}',
        '.dsh-snap-table{width:100%;border-collapse:collapse;margin:0 0 14px}',
        '.dsh-snap-table th{opacity:.55;font-weight:500;text-align:left;padding:4px 8px;border-bottom:1px solid var(--dsh-border,#ccc)}',
        '.dsh-snap-table td{padding:5px 8px;border-bottom:1px solid var(--dsh-border,#5553)}',
        '.dsh-snap-code{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:rgba(127,127,127,.12);border-radius:6px;padding:6px 8px;word-break:break-all;display:block;margin:4px 0}',
        '.dsh-snap-hint{margin:0 0 14px;border:1px solid var(--dsh-border,#ccc);border-radius:8px;padding:10px 12px}',
        '.dsh-snap-doctor{margin:6px 0 0;font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;opacity:.85}',
        '.dsh-snap-tag{display:inline-block;border:1px solid var(--dsh-border,#ccc);border-radius:4px;font-size:11px;padding:0 5px;margin-left:6px;opacity:.8}',
      ].join('\n')
      document.head.appendChild(style)
    }

    /* ---------------- 组件 ---------------- */
    function SnapTab(props) {
      var t = props.t
      var stateP = useState(null)
      var panel = stateP[0]; var setPanel = stateP[1]
      var stateE = useState(null)
      var error = stateE[0]; var setError = stateE[1]
      var stateB = useState(false)
      var busy = stateB[0]; var setBusy = stateB[1]
      var stateN = useState('')
      var note = stateN[0]; var setNote = stateN[1]
      var stateD = useState(null)
      var doctor = stateD[0]; var setDoctor = stateD[1]
      var stateC = useState(false)
      var copied = stateC[0]; var setCopied = stateC[1]
      var stateS = useState(null)
      var selSnap = stateS[0]; var setSelSnap = stateS[1]

      var reload = useCallback(function () {
        fetchJson('/dsh-snap/panel').then(function (data) {
          if (data && data.ok) { setPanel(data); setError(null) } // 成功后清错误行（曾常驻误导）
          else setError(data && data.message || 'unknown')
        }).catch(function (e) { setError(String(e && e.message || e)) })
      }, [])
      useEffect(function () { reload() }, [reload])

      var act = useCallback(function (fn, okText) {
        setBusy(true); setNote('')
        fn().then(function (data) {
          setBusy(false)
          // E5（0.7.4 审计 P2）：领域结果（data.ok === false 但带 code/计数字段）不是传输
          // 错误——交给 okText formatter 呈现细节（verify 的缺失/被改计数曾显示成 'error'）
          var isDomainResult = data && data.ok === false && (data.code || data.missingCount !== undefined || data.modifiedCount !== undefined || data.hashMismatchCount !== undefined)
          if (data && (data.ok || isDomainResult) && okText) {
            setNote(okText(data))
            reload()
          } else if (data && data.ok) {
            reload()
          } else setNote((data && data.message) || (data && data.code) || 'error')
        }).catch(function (e) {
          setBusy(false)
          // C5（0.7.4 审计 P2）：12s abort 只放弃 fetch——同步后端仍在跑。区分"仍运行"与失败
          var msg = String(e && e.message || e)
          if (e && e.name === 'TimeoutError' || /timed?\s?out|abort/i.test(msg)) {
            setNote(t('stillRunning'))
          } else setNote(msg)
        })
      }, [reload, t])

      var children = []
      children.push(createElement('h3', { key: 't', style: { marginTop: 0 } }, t('title')))
      children.push(createElement('p', { key: 'l', className: 'dsh-snap-lead' }, t('lead')))
      if (panel && panel.uncleanBoot) {
        // G5：归因横幅（suspects / loops / 崩溃前快照还原命令）；attribution 缺失时回退单行
        var attr = panel.attribution
        var bannerKids = [createElement('div', { key: 'u0' }, '⚠️ ', t('unclean'))]
        if (attr) {
          if (attr.suspects && attr.suspects.length) {
            bannerKids.push(createElement('div', { key: 'u1', style: { marginTop: 4 } },
              t('attrSuspects'),
              attr.suspects.map(function (s, i) {
                return createElement('span', { key: s.pkg },
                  (i ? '、' : '') + s.pkg + '（' + s.confidence + '）')
              })))
          } else if (attr.crashes && attr.crashes.length && !attr.shellHandshake) {
            // 全 shell 握手崩溃时省略通用文案（P2-03：曾在此显示"未发现插件变更"——误导，诊断块会说明真因）
            bannerKids.push(createElement('div', { key: 'u2', style: { marginTop: 4, opacity: .75 } }, t('attrNoSuspects')))
          }
          if (attr.shellHandshake) {
            bannerKids.push(createElement('div', { key: 'u1s', style: { marginTop: 4 } },
              '⚠️ ' + t('attrShell') + (attr.shellHandshake.all ? t('attrShellAll') : t('attrShellPart')) +
              attr.shellHandshake.count + t('attrShellOf') + attr.shellHandshake.allCount + t('attrShellTimes')))
            bannerKids.push(createElement('div', { key: 'u1s2', style: { marginTop: 2, opacity: .75 } }, t('attrShellFix')))
          }
          if (attr.loops && attr.loops.length) {
            var lp = attr.loops[0]
            bannerKids.push(createElement('div', { key: 'u3', style: { marginTop: 4 } },
              t('attrLoop') + lp.count + t('attrTimes') + '（' + lp.first + ' → ' + lp.last + '）'))
          }
          if (attr.restoreHint && attr.restoreHint.command) {
            bannerKids.push(createElement('div', { key: 'u4', style: { marginTop: 6 } }, t('attrRestore')))
            bannerKids.push(createElement('code', { key: 'u5', className: 'dsh-snap-code' }, attr.restoreHint.command))
          }
        }
        children.push(createElement('div', { key: 'u', className: 'dsh-snap-banner' }, createElement(Fragment, null, bannerKids)))
      }
      if (panel && panel.harnessChange && panel.harnessChange.last) {
        // harness 变更哨兵横幅（破坏性更新防线）：更新后首启提示 + 事件时间
        var hc = panel.harnessChange.last
        children.push(createElement('div', { key: 'hc', className: 'dsh-snap-banner', style: { borderLeft: '4px solid #b8860b' } },
          createElement(Fragment, null,
            createElement('div', { key: 'h0' }, 'ℹ️ ', t('harnessChange'), '（', hc.to && hc.to.harnessDeps ? hc.to.harnessDeps : t('harnessUnknown'), '）'),
            createElement('div', { key: 'h1', style: { marginTop: 4, opacity: .75 } }, t('harnessChangeHint')),
            createElement('code', { key: 'h2', className: 'dsh-snap-code' }, panel.restoreHint))))
      }
      children.push(createElement('div', { key: 'a', className: 'dsh-snap-actions' },
        createElement('button', {
          className: 'dsh-snap-button', disabled: busy,
          onClick: function () { act(function () { return fetchJson('/dsh-snap/snapshot-now', { method: 'POST' }) }, function (d) { return t('snapDone') + ' ' + d.id + '（' + d.files + ' ' + t('webFiles') + '）' }) },
        }, t('snapNow')),
        createElement('button', {
          className: 'dsh-snap-button', disabled: busy,
          onClick: function () { act(function () { return fetchJson('/dsh-snap/open-store', { method: 'POST' }) }) },
        }, t('openStore')),
        createElement('button', {
          className: 'dsh-snap-button', disabled: busy,
          onClick: function () {
            act(function () { return fetchJson('/dsh-snap/verify', { method: 'POST' }) }, function (d) {
              if (!d || d.code === 'no-snapshot') return t('empty')
              if (d.ok) return t('verifyOk') + '（' + d.checked + '）'
              var parts = []
              if (d.missingCount) parts.push(t('verifyMiss') + ' ' + d.missingCount)
              if (d.modifiedCount) parts.push(t('verifyMod') + ' ' + d.modifiedCount)
              if (d.hashMismatchCount) parts.push(t('verifyHash') + ' ' + d.hashMismatchCount)
              return t('verifyBad') + '：' + parts.join(' / ')
            })
          },
        }, t('verify')),
        createElement('button', {
          className: 'dsh-snap-button', disabled: busy,
          onClick: function () {
            setBusy(true)
            fetchJson('/dsh-snap/doctor').then(function (d) { setBusy(false); setDoctor(d) }).catch(function (e) { setBusy(false); setDoctor({ ok: false, checks: [{ id: 'error', ok: false, detail: String(e) }] }) })
          },
        }, t('doctor')),
      ))
      if (note) children.push(createElement('div', { key: 'n', className: 'dsh-snap-lead' }, note))
      if (error) children.push(createElement('div', { key: 'e', className: 'dsh-snap-lead' }, t('loadError'), error))

      if (!panel && !error) {
        children.push(createElement('div', { key: 'ld', className: 'dsh-snap-lead' }, t('loading')))
      } else if (panel) {
        if (!panel.snapshots || panel.snapshots.length === 0) {
          children.push(createElement('div', { key: 'em', className: 'dsh-snap-lead' }, t('empty')))
          if (panel.corrupted && panel.corrupted.length) {
            children.push(createElement('div', { key: 'cc', className: 'dsh-snap-lead' }, t('corrupt'), panel.corrupted.join(', ')))
          }
        } else {
          var rows = panel.snapshots.map(function (s, i) {
            return createElement('tr', { key: s.id, onClick: function () { setSelSnap(s.id) }, style: { cursor: 'pointer', background: selSnap === s.id ? 'rgba(59,130,246,.12)' : undefined } },
              createElement('td', null, fmtTime(s.time)),
              createElement('td', null,
                triggerLabel(s.trigger, triggerDict(t)),
                s.guard ? createElement('span', { className: 'dsh-snap-tag' }, t('guard')) : null,
                s.manual && s.trigger === 'manual' ? createElement('span', { className: 'dsh-snap-tag' }, t('manual')) : null,
                s.complete === false ? createElement('span', { className: 'dsh-snap-tag' }, t('incomplete')) : null),
              createElement('td', null, s.spec || s.label || ''),
              createElement('td', null, s.files === null ? '' : s.files + ' · ' + fmtBytes(s.bytes)),
              createElement('td', null, s.durationMs === null ? '' : (s.durationMs / 1000).toFixed(1) + 's'),
            )
          })
          children.push(createElement('table', { key: 'tb', className: 'dsh-snap-table' },
            createElement('thead', null, createElement('tr', null,
              createElement('th', null, t('colTime')),
              createElement('th', null, t('colTrigger')),
              createElement('th', null, t('colSpec')),
              createElement('th', null, t('colSize')),
              createElement('th', null, t('colDur')))),
            createElement('tbody', null, rows)))
          if (panel.corrupted && panel.corrupted.length) {
            children.push(createElement('div', { key: 'c2', className: 'dsh-snap-lead' }, t('corrupt'), panel.corrupted.join(', ')))
          }
          // G10 bisect：选中时间线行 → 还原命令预填到该点 + 其后安装清单
          var selIdx = selSnap ? panel.snapshots.findIndex(function (s) { return s.id === selSnap }) : -1
          var afterInstalls = []
          if (selIdx > 0) {
            var seen = {}
            for (var bi = 0; bi < selIdx; bi++) {
              var bs = panel.snapshots[bi]
              var isInstallRow = bs.trigger === 'web-install' || bs.trigger === 'cli-install' || (typeof bs.trigger === 'string' && bs.trigger.indexOf('agent:install') === 0)
              if (isInstallRow && bs.spec && !seen[bs.spec]) { seen[bs.spec] = 1; afterInstalls.push(bs.spec) }
            }
          }
          var bisectCmd = selIdx >= 0 ? panel.restoreHint.replace(/restore last$/, 'restore ' + selSnap) : panel.restoreHint
          children.push(createElement('div', { key: 'rh', className: 'dsh-snap-hint' },
            createElement('div', { style: { opacity: .7, fontSize: 12, marginBottom: 4 } }, t('bisect')),
            createElement('div', null,
              t('restoreHint') + ' ',
              createElement('span', { style: { opacity: .6, fontSize: 12 } }, selIdx >= 0 ? t('bisectSel') + ' ' + selSnap : t('bisectDefault'))),
            createElement('code', { className: 'dsh-snap-code' }, bisectCmd),
            selIdx > 0 ? createElement('div', { style: { fontSize: 12, marginTop: 4 } },
              t('bisectAfter') + afterInstalls.length + ' → ' + (afterInstalls.join('、') || t('bisectNone'))) : null,
            createElement('div', { style: { opacity: .7, fontSize: 12 } }, t('restoreBat')),
            createElement('button', { className: 'dsh-snap-button', style: { marginTop: 6 }, onClick: function () {
              var text = bisectCmd
              try { if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text) } catch (e) { /* 可容忍 */ }
              setCopied(true)
              setTimeout(function () { setCopied(false) }, 1600)
            } }, copied ? t('copied') : t('copy')),
          ))
        }
      }
      if (doctor) {
        children.push(createElement('div', { key: 'dr' },
          createElement('div', null, t('doctorTitle') + '：', doctor.ok === true ? t('doctorOk') : t('doctorBad')),
          createElement('div', { className: 'dsh-snap-doctor' },
            (doctor.checks || []).map(function (c) { return (c.ok ? '✅ ' : '⚠️ ') + c.id + ': ' + c.detail }).join('\n'))))
      }
      return createElement('div', { className: 'dsh-snap-root', 'data-dsh-snap': '' }, createElement(Fragment, null, children))
    }

    /* ---------------- 挂载 ---------------- */
    var inject = ['slots', 'locale']

    function apply(ctx) {
      ctx.effect(function () { return ctx.locale.register(NS, locales) }, 'dsh-snap: dictionaries')
      ctx.effect(function () { return installStyles() }, 'dsh-snap: stylesheet')
      ctx.inject(['slots'], function (scope) {
        var t = null
        try { t = scope.locale.bind(NS) } catch (e) { t = function (k) { return (locales['zh'] || {})[k] || k } }
        var api = {
          panel: function () { return fetchJson('/dsh-snap/panel') },
        }
        void api // 保留注入面（外部 tab 宿主可能消费 api.panel）；组件内走 fetchJson
        scope.slots.inject('settings.plugins.tab', function () {
          return scope.slots.register({
            name: 'settings.plugins.tab',
            id: 'dsh-snap',
            order: 21,
            label: function () { return t('tab') },
            locale: NS,
            inject: function () { return { api: api, t: t } },
          }, SnapTab)
        })
      })
    }

    return {
      name: NS,
      inject: inject,
      apply: apply,
      NS: NS,
    }
  },
})
