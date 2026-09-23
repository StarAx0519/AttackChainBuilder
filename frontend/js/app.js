/**
 * =============================================================================
 * frontend/js/app.js — 攻击链路模块前端交互逻辑
 * =============================================================================
 */
(() => {
  // 后端 API 前缀；可由页面全局变量覆盖
  const API_BASE = window.QY_API_BASE || '/api';

  /** 会话状态：保存最近一次映射/链路结果，供二次构建与筛选使用 */
  const state = {
    batchId: null,
    contentHash: null,
    mapped: [],
    filteredMapped: [],
    chains: [],
    coverage: null,
    stats: null,
    file: null,
    /** 用户明确选择的数据源：'file' | 'text' | null */
    preferredSource: null,
    /** 是否在「文件+文本并存」时由用户显式点选过数据源 */
    sourceExplicit: false,
    mongoOk: false,
    /** 本批次是否已产出过真实结果（用于显示统计入库按钮） */
    hasComputedBatch: false,
    /** 库内累计（打开/刷新时从 Mongo 读取） */
    cumulative: {
      mappedAlertCount: 0,
      attackChainCount: 0
    },
    /** 本会话是否已执行映射 / 构链 */
    sessionMapped: false,
    sessionBuilt: false
  };

  const $ = (id) => document.getElementById(id);

  const els = {
    apiStatus: $('apiStatus'),
    statMappedCum: $('statMappedCum'),
    statMappedSession: $('statMappedSession'),
    statMappedSub: $('statMappedSub'),
    metricMappedSession: $('metricMappedSession'),
    metricAccuracy: $('metricAccuracy'),
    metricCoverage: $('metricCoverage'),
    metricChainsSession: $('metricChainsSession'),
    statAccuracy: $('statAccuracy'),
    statAccuracySub: $('statAccuracySub'),
    statChainsCum: $('statChainsCum'),
    statChainsSession: $('statChainsSession'),
    statChainsSub: $('statChainsSub'),
    statCoverage: $('statCoverage'),
    statCoverageSub: $('statCoverageSub'),
    fileInput: $('fileInput'),
    fileDrop: $('fileDrop'),
    fileName: $('fileName'),
    btnClearFile: $('btnClearFile'),
    fileCol: $('fileCol'),
    textCol: $('textCol'),
    inputSourceBar: $('inputSourceBar'),
    inputSourceStatus: $('inputSourceStatus'),
    inputSourcePick: $('inputSourcePick'),
    sourceFile: $('sourceFile'),
    sourceText: $('sourceText'),
    sourceModal: $('sourceModal'),
    sourceModalMsg: $('sourceModalMsg'),
    sourceModalClose: $('sourceModalClose'),
    sourceModalFile: $('sourceModalFile'),
    sourceModalText: $('sourceModalText'),
    alertText: $('alertText'),
    btnMap: $('btnMap'),
    btnBuild: $('btnBuild'),
    btnPipeline: $('btnPipeline'),
    btnPickDbSample: $('btnPickDbSample'),
    sampleModal: $('sampleModal'),
    sampleModalClose: $('sampleModalClose'),
    sampleModalHint: $('sampleModalHint'),
    sampleList: $('sampleList'),
    samplePreview: $('samplePreview'),
    sampleModalApply: $('sampleModalApply'),
    btnSaveAlerts: $('btnSaveAlerts'),
    btnSaveChains: $('btnSaveChains'),
    btnSaveStats: $('btnSaveStats'),
    persistProgress: $('persistProgress'),
    persistProgressTitle: $('persistProgressTitle'),
    persistProgressPct: $('persistProgressPct'),
    persistBarFill: $('persistBarFill'),
    persistSteps: $('persistSteps'),
    persistMsg: $('persistMsg'),
    mapTable: $('mapTable').querySelector('tbody'),
    coverageMatrix: $('coverageMatrix'),
    chainList: $('chainList'),
    batchIdLabel: $('batchIdLabel'),
    batchHint: $('batchHint'),
    filterField: $('filterField'),
    filterKeyword: $('filterKeyword'),
    filterQuality: $('filterQuality'),
    filterMethod: $('filterMethod'),
    btnClearFilter: $('btnClearFilter')
  };

  /** 空值统一显示为「N/A」 */
  function displayOrNone(v) {
    if (v == null || String(v).trim() === '') return 'N/A';
    return String(v);
  }

  function cellEmptyClass(v) {
    return v == null || String(v).trim() === '' ? ' cell-empty' : '';
  }

  function getDescription(row) {
    return (
      row.description ||
      row.original?.description ||
      row.original?.message ||
      row.original?.detail ||
      null
    );
  }

  /** 按筛选项过滤 mapped 列表 */
  function applyFilters() {
    const field = els.filterField?.value || 'all';
    const kw = (els.filterKeyword?.value || '').trim().toLowerCase();
    const quality = els.filterQuality?.value || '';
    const method = els.filterMethod?.value || '';

    state.filteredMapped = (state.mapped || []).filter((row) => {
      const m = row.mapping || {};
      if (quality && m.quality !== quality) return false;
      if (method && m.method !== method) return false;
      if (!kw) return true;

      const desc = getDescription(row) || '';
      const bag = {
        all: [
          row.title,
          row.attackType,
          row.srcIp,
          row.dstIp,
          row.host,
          desc,
          m.primary,
          m.techniqueName,
          m.tacticName,
          m.tacticId,
          m.quality,
          m.qualityLabel,
          m.method,
          m.methodLabel,
          fmtTime(row.timestamp)
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase(),
        title: String(row.title || '').toLowerCase(),
        attackType: String(row.attackType || '').toLowerCase(),
        srcIp: String(row.srcIp || '').toLowerCase(),
        dstIp: String(row.dstIp || '').toLowerCase(),
        host: String(row.host || '').toLowerCase(),
        description: String(desc).toLowerCase(),
        technique: `${m.primary || ''} ${m.techniqueName || ''}`.toLowerCase(),
        tactic: `${m.tacticName || ''} ${m.tacticId || ''}`.toLowerCase(),
        quality: String(m.quality || '').toLowerCase(),
        method: String(m.method || '').toLowerCase()
      };
      const hay = bag[field] != null ? bag[field] : bag.all;
      return hay.includes(kw);
    });

    paintMapTable(state.filteredMapped);
  }

  function fmtTime(rowOrIso) {
    // 兼容旧调用 fmtTime(iso) 与新调用 fmtTime(row)
    if (rowOrIso && typeof rowOrIso === 'object') {
      const row = rowOrIso;
      if (row.timeDisplay) return row.timeDisplay;
      if (row.timePrecision === 'month' && row.timestamp) {
        const d = new Date(row.timestamp);
        if (!Number.isNaN(d.getTime())) {
          return `${d.getUTCFullYear()}年${d.getUTCMonth() + 1}月`;
        }
      }
      if (!row.timestamp) return '没有';
      return fmtTimeIso(row.timestamp, row.timePrecision);
    }
    return fmtTimeIso(rowOrIso);
  }

  function fmtTimeIso(iso, precision) {
    if (!iso) return '没有';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    if (precision === 'month') {
      return `${d.getUTCFullYear()}年${d.getUTCMonth() + 1}月`;
    }
    if (precision === 'day') {
      return d.toISOString().slice(0, 10);
    }
    return d.toISOString().replace('T', ' ').slice(0, 19);
  }

  function paintMapTable(rows) {
    const total = state.mapped.length;
    const shown = rows.length;
    els.mapTable.innerHTML = '';

    if (!total) {
      els.mapTable.innerHTML =
        '<tr><td colspan="12" style="color:var(--muted);text-align:center">暂无映射结果</td></tr>';
      return;
    }
    if (!shown) {
      els.mapTable.innerHTML =
        '<tr><td colspan="12" style="color:var(--muted);text-align:center">无匹配筛选条件的记录</td></tr>';
      return;
    }

    const frag = document.createDocumentFragment();
    rows.forEach((row, idx) => {
      const m = row.mapping || {};
      const desc = getDescription(row);
      const step = row.stepLabel || (row.stepIndex ? `攻击步骤${row.stepIndex}` : '—');
      const techList =
        Array.isArray(m.techniques) && m.techniques.length
          ? m.techniques
          : m.primary
            ? [{ id: m.primary, name: m.techniqueName }]
            : [];
      const tacticList =
        Array.isArray(m.tactics) && m.tactics.length
          ? m.tactics
          : m.tacticId
            ? [{ id: m.tacticId, name: m.tacticName }]
            : [];
      const techHtml = techList.length
        ? techList
            .map(
              (t) =>
                `<div class="mono">${escapeHtml(t.id || '')}<span style="color:var(--muted);font-weight:400"> ${escapeHtml(t.name || '')}</span></div>`
            )
            .join('')
        : `<span class="cell-empty">没有</span>`;
      const tacticHtml = tacticList.length
        ? tacticList
            .map(
              (t) =>
                `<div>${escapeHtml(t.name || '')}<div class="mono" style="color:var(--muted)">${escapeHtml(t.id || '')}</div></div>`
            )
            .join('')
        : `<span class="cell-empty">没有</span>`;

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono">${escapeHtml(step)}</td>
        <td class="mono">${escapeHtml(fmtTime(row))}</td>
        <td class="cell-text">${escapeHtml(displayOrNone(row.title))}</td>
        <td class="mono${cellEmptyClass(row.srcIp)}">${escapeHtml(displayOrNone(row.srcIp))}</td>
        <td class="mono${cellEmptyClass(row.dstIp)}">${escapeHtml(displayOrNone(row.dstIp))}</td>
        <td class="cell-text${cellEmptyClass(row.host)}">${escapeHtml(displayOrNone(row.host))}</td>
        <td class="cell-text">${techHtml}</td>
        <td class="cell-text">${tacticHtml}</td>
        <td class="mono">${m.confidence != null ? Number(m.confidence).toFixed(2) : '没有'}</td>
        <td class="cell-text ${qualityClass(m.quality)}">${escapeHtml(displayOrNone(m.qualityLabel || m.quality))}</td>
        <td class="cell-text">${escapeHtml(displayOrNone(m.methodLabel || methodLabelOf(m.method)))}</td>
        <td><button type="button" class="btn-linkish btn-view-desc" data-idx="${idx}">查看</button></td>
      `;
      // store description on button via dataset index into filtered list
      frag.appendChild(tr);
    });
    els.mapTable.appendChild(frag);

    els.mapTable.querySelectorAll('.btn-view-desc').forEach((btn) => {
      btn.addEventListener('click', () => {
        const i = Number(btn.getAttribute('data-idx'));
        const row = rows[i];
        openDescModal(row);
      });
    });
  }

  function openDescModal(row) {
    const modal = $('descModal');
    const body = $('descModalBody');
    const title = $('descModalTitle');
    if (!modal || !body) return;
    const desc = getDescription(row);
    title.textContent = row.stepLabel
      ? `${row.stepLabel} · 告警描述`
      : `告警描述 · ${row.title || ''}`;

    const mainText = desc && String(desc).trim() ? String(desc).trim() : '没有';
    const metaParts = [
      row.device ? `检测设备: ${row.device}` : null,
      row.destNodeId ? `目的节点ID(dnode): ${row.destNodeId}` : null,
      row.srcNodeId ? `源节点ID(snode): ${row.srcNodeId}` : null
    ].filter(Boolean);

    body.replaceChildren();
    const main = document.createElement('div');
    main.className = 'desc-modal-main';
    main.textContent = mainText;
    body.appendChild(main);

    if (metaParts.length) {
      const meta = document.createElement('div');
      meta.className = 'desc-modal-meta';
      meta.textContent = metaParts.join('\n');
      body.appendChild(meta);
    }
    modal.hidden = false;
  }

  function bindDescModal() {
    const modal = $('descModal');
    const closeBtn = $('descModalClose');
    closeBtn?.addEventListener('click', () => {
      if (modal) modal.hidden = true;
    });
    modal?.addEventListener('click', (e) => {
      if (e.target === modal) modal.hidden = true;
    });
  }

  function renderMapped(mapped) {
    state.mapped = mapped || [];
    // 新结果时清空关键词以外的筛选也可保留；这里保留筛选条件并重算
    applyFilters();
  }

  function bindFilters() {
    const rerun = () => applyFilters();
    els.filterField?.addEventListener('change', rerun);
    els.filterQuality?.addEventListener('change', rerun);
    els.filterMethod?.addEventListener('change', rerun);
    els.filterKeyword?.addEventListener('input', rerun);
    els.btnClearFilter?.addEventListener('click', () => {
      if (els.filterField) els.filterField.value = 'all';
      if (els.filterKeyword) els.filterKeyword.value = '';
      if (els.filterQuality) els.filterQuality.value = '';
      if (els.filterMethod) els.filterMethod.value = '';
      applyFilters();
    });
  }

  function setBusy(busy) {
    [els.btnMap, els.btnBuild, els.btnPipeline, els.btnPickDbSample].forEach((b) => {
      if (b) b.disabled = busy;
    });
    if (!busy) updatePersistButtons();
    else {
      [els.btnSaveAlerts, els.btnSaveChains, els.btnSaveStats].forEach((b) => {
        if (b) b.disabled = true;
      });
    }
  }

  /** 结果就绪后显示对应分区右上角入库按钮；未就绪则 hidden */
  function updatePersistButtons() {
    const hasMapped = (state.mapped || []).length > 0 && !!state.batchId;
    const hasChains = (state.chains || []).length > 0 && !!state.batchId;
    const hasStats =
      state.hasComputedBatch &&
      !!state.batchId &&
      !!state.stats &&
      !!state.coverage;

    const setVisible = (btn, visible) => {
      if (!btn) return;
      btn.hidden = !visible;
      btn.disabled = !visible;
    };
    setVisible(els.btnSaveAlerts, hasMapped);
    setVisible(els.btnSaveChains, hasChains);
    setVisible(els.btnSaveStats, hasStats);
  }

  let persistHideTimer = null;
  let persistFadeTimer = null;

  function clearPersistAutoHide() {
    if (persistHideTimer) {
      clearTimeout(persistHideTimer);
      persistHideTimer = null;
    }
    if (persistFadeTimer) {
      clearTimeout(persistFadeTimer);
      persistFadeTimer = null;
    }
  }

  function schedulePersistFadeOut(delayMs = 2800) {
    clearPersistAutoHide();
    if (!els.persistProgress) return;
    persistHideTimer = setTimeout(() => {
      els.persistProgress.classList.add('is-fading');
      persistFadeTimer = setTimeout(() => {
        els.persistProgress.hidden = true;
        els.persistProgress.classList.remove(
          'is-fading',
          'is-ok',
          'is-err',
          'is-cover',
          'is-partial'
        );
        persistFadeTimer = null;
      }, 900);
      persistHideTimer = null;
    }, delayMs);
  }

  function showPersistProgress({ title, pct, steps, msg, status, persistKind }) {
    if (!els.persistProgress) return;
    clearPersistAutoHide();
    els.persistProgress.classList.remove('is-fading', 'is-ok', 'is-err', 'is-cover', 'is-partial');
    els.persistProgress.hidden = false;
    els.persistProgress.classList.toggle('is-ok', status === 'ok' && (!persistKind || persistKind === 'all_new'));
    els.persistProgress.classList.toggle('is-cover', status === 'ok' && persistKind === 'all_exist');
    els.persistProgress.classList.toggle('is-partial', status === 'ok' && persistKind === 'partial');
    els.persistProgress.classList.toggle('is-err', status === 'err');
    if (els.persistProgressTitle) els.persistProgressTitle.textContent = title || '入库进度';
    if (els.persistProgressPct) els.persistProgressPct.textContent = `${Math.round(pct || 0)}%`;
    if (els.persistBarFill) els.persistBarFill.style.width = `${Math.min(100, Math.max(0, pct || 0))}%`;
    if (els.persistSteps) {
      els.persistSteps.innerHTML = '';
      const msgText = String(msg || '').trim();
      (steps || []).forEach((s) => {
        const text = String(s.message || s.name || '').trim();
        // 避免与底部说明重复显示同一句话
        if (!text || (msgText && text === msgText)) return;
        const li = document.createElement('li');
        li.className = s.status || '';
        li.textContent = text;
        els.persistSteps.appendChild(li);
      });
    }
    if (els.persistMsg) els.persistMsg.textContent = msg || '';

    // 成功(100%)或失败：停留约 3 秒后淡出消失
    if (status === 'ok' || status === 'err') {
      schedulePersistFadeOut(3200);
    }
  }

  async function doPersist(mode) {
    const labels = {
      alerts: '存入映射结果',
      chains: '存入攻击链路',
      stats: '存入统计覆盖'
    };
    const label = labels[mode] || '入库';

    const failToast = (msg) => {
      showPersistProgress({
        title: '入库失败',
        pct: 0,
        steps: [{ name: mode, status: 'fail', message: '入库未完成' }],
        msg: msg || '入库失败',
        status: 'err'
      });
    };

    if (!state.batchId) {
      failToast('请先执行映射或一键流水线，再入库');
      return;
    }
    if (mode === 'alerts' && !state.mapped.length) {
      failToast('没有可入库的映射结果');
      return;
    }
    if (mode === 'chains' && !state.chains.length) {
      failToast('没有可入库的攻击链路，请先构建链路');
      return;
    }
    if (mode === 'stats' && (!state.stats || !state.coverage)) {
      failToast('没有可入库的统计/覆盖数据');
      return;
    }
    if (!state.mongoOk) {
      const go = confirm(
        '检测到 MongoDB 可能未连接，仍要尝试入库吗？失败时会在右下角提示原因。'
      );
      if (!go) return;
    }

    const summary =
      mode === 'alerts'
        ? `写入集合 mappedalerts：${state.mapped.length} 条（batchId: ${state.batchId}）`
        : mode === 'chains'
          ? `写入集合 attackchains：${state.chains.length} 条（batchId: ${state.batchId}）`
          : `写入集合 sessionstats：统计四指标 + 覆盖矩阵（batchId: ${state.batchId}）`;

    if (!confirm(`确认${label}？\n\n${summary}`)) return;

    const planSteps = [
      {
        name: mode,
        status: 'running',
        message:
          mode === 'alerts'
            ? '准备写入 mappedalerts…'
            : mode === 'chains'
              ? '准备写入 attackchains…'
              : '准备写入 sessionstats…'
      }
    ];

    setBusy(true);
    showPersistProgress({
      title: `正在${label}…`,
      pct: 12,
      steps: planSteps,
      msg: '已提交入库请求，请稍候…',
      status: 'running'
    });

    let tick = 12;
    const timer = setInterval(() => {
      tick = Math.min(88, tick + 8);
      if (els.persistBarFill) els.persistBarFill.style.width = `${tick}%`;
      if (els.persistProgressPct) els.persistProgressPct.textContent = `${tick}%`;
    }, 280);

    try {
      const data = await api('/persist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          batchId: state.batchId,
          contentHash: state.contentHash,
          mapped: state.mapped,
          chains: state.chains,
          stats: state.stats,
          coverage: state.coverage
        })
      });

      clearInterval(timer);
      if (data.batchId) {
        state.batchId = data.batchId;
        if (els.batchIdLabel) els.batchIdLabel.textContent = `batchId: ${data.batchId}`;
        // batchId 变化时同步刷新链路名称（攻击链路（batchId））
        if (state.chains.length) renderChains(state.chains);
      }
      if (data.contentHash) state.contentHash = data.contentHash;
      const kind = data.persistKind || (data.reused || data.skipped ? 'all_exist' : 'all_new');
      const titleByKind = {
        all_new: '保存成功',
        all_exist: '已存在，无需重复入库',
        partial: '保存成功'
      };
      showPersistProgress({
        title: data.title || titleByKind[kind] || '保存成功',
        pct: 100,
        steps: [],
        msg: data.message || `${label}成功`,
        status: 'ok',
        persistKind: kind
      });
      if (els.batchHint) els.batchHint.textContent = data.message || `${label}成功`;
      // 入库成功后刷新库内累计数字
      await refreshCumulativeStats();
    } catch (e) {
      clearInterval(timer);
      // 仅右下角提示，不再用浏览器 alert（避免与淡出冲突、文案重复）
      failToast(e.message || '入库失败，请检查 MongoDB 是否已启动');
    } finally {
      setBusy(false);
    }
  }

  function friendlyHttpError(res, data) {
    if (data && typeof data.error === 'string' && data.error.trim()) {
      return data.error.trim();
    }
    if (res.status === 404) {
      return '入库接口未找到（404）。请重启后端服务后再试。';
    }
    if (res.status === 503) {
      return 'MongoDB 未连接，无法入库。请启动数据库后刷新页面。';
    }
    if (res.status === 400) {
      return '请求参数有误，无法入库';
    }
    if (res.status >= 500) {
      return `服务器错误（${res.status}），入库失败`;
    }
    const st = (res.statusText || '').trim();
    if (st && st.toLowerCase() !== 'not found') {
      return st;
    }
    return `入库请求失败（HTTP ${res.status || '?'}）`;
  }

  async function api(path, options = {}) {
    const res = await fetch(`${API_BASE}${path}`, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(friendlyHttpError(res, data));
    return data;
  }

  /** 本次指标框：数值为 0 填黄，非 0 填绿 */
  function setSessionMetricFill(el, numericValue) {
    if (!el) return;
    const n = Number(numericValue);
    const isZero = !Number.isFinite(n) || n === 0;
    el.classList.toggle('fill-zero', isZero);
    el.classList.toggle('fill-done', !isZero);
  }

  /**
   * 刷新顶部统计栏：历史（蓝灰）+ 本次（0 黄 / 非 0 绿）
   */
  function renderTopStats() {
    const cum = state.cumulative || {};
    const stats = state.stats || {};
    const cumMapped = cum.mappedAlertCount ?? 0;
    const cumChains = cum.attackChainCount ?? 0;

    if (els.statMappedCum) els.statMappedCum.textContent = String(cumMapped);
    if (els.statChainsCum) els.statChainsCum.textContent = String(cumChains);

    let sessionMapped = 0;
    let accuracyNum = 0;
    let coverageNum = 0;

    if (state.sessionMapped) {
      sessionMapped = stats.totalAlertCount ?? stats.mappedAlertCount ?? state.mapped.length ?? 0;
      accuracyNum = Number(stats.mappingAccuracy);
      if (!Number.isFinite(accuracyNum)) {
        const pct = String(stats.mappingAccuracyPercent || '0').replace('%', '');
        accuracyNum = Number(pct) || 0;
      } else {
        accuracyNum = accuracyNum * 100;
      }
      coverageNum = Number(stats.tacticCoverage);
      if (!Number.isFinite(coverageNum)) {
        const pct = String(stats.tacticCoveragePercent || '0').replace('%', '');
        coverageNum = Number(pct) || 0;
      } else {
        coverageNum = coverageNum * 100;
      }

      if (els.statMappedSession) els.statMappedSession.textContent = String(sessionMapped);
      if (els.statMappedSub) {
        els.statMappedSub.textContent = `本次已映射 ${sessionMapped} 条告警`;
        els.statMappedSub.classList.remove('is-pending');
      }
      if (els.statAccuracy) els.statAccuracy.textContent = stats.mappingAccuracyPercent || '0%';
      if (els.statAccuracySub) {
        els.statAccuracySub.textContent = 'excellent / good 占比';
        els.statAccuracySub.classList.remove('is-pending');
      }
      if (els.statCoverage) els.statCoverage.textContent = stats.tacticCoveragePercent || '0%';
      if (els.statCoverageSub) {
        els.statCoverageSub.textContent = `${stats.coveredTactics ?? 0} / ${stats.totalTactics ?? 14} 战术`;
        els.statCoverageSub.classList.remove('is-pending');
      }
    } else {
      if (els.statMappedSession) els.statMappedSession.textContent = '0';
      if (els.statMappedSub) {
        els.statMappedSub.textContent = '待用户执行下一次映射';
        els.statMappedSub.classList.add('is-pending');
      }
      if (els.statAccuracy) els.statAccuracy.textContent = '0%';
      if (els.statAccuracySub) {
        els.statAccuracySub.textContent = '';
        els.statAccuracySub.classList.remove('is-pending');
      }
      if (els.statCoverage) els.statCoverage.textContent = '0%';
      if (els.statCoverageSub) {
        els.statCoverageSub.textContent = '';
        els.statCoverageSub.classList.remove('is-pending');
      }
    }

    let sessionChains = 0;
    if (state.sessionBuilt) {
      sessionChains = stats.attackChainCount ?? state.chains.length ?? 0;
      if (els.statChainsSession) els.statChainsSession.textContent = String(sessionChains);
      if (els.statChainsSub) {
        els.statChainsSub.textContent = `本次已还原 ${sessionChains} 条攻击链路`;
        els.statChainsSub.classList.remove('is-pending');
      }
    } else {
      if (els.statChainsSession) els.statChainsSession.textContent = '0';
      if (els.statChainsSub) {
        els.statChainsSub.textContent = '待用户执行下一次构建';
        els.statChainsSub.classList.add('is-pending');
      }
    }

    setSessionMetricFill(els.metricMappedSession, sessionMapped);
    setSessionMetricFill(els.metricAccuracy, accuracyNum);
    setSessionMetricFill(els.metricChainsSession, sessionChains);
    setSessionMetricFill(els.metricCoverage, coverageNum);
  }

  /** @deprecated 兼容旧调用名 → 更新本会话 stats 后刷新顶栏 */
  function renderStats(stats) {
    if (stats) state.stats = stats;
    renderTopStats();
  }

  async function refreshCumulativeStats() {
    try {
      const data = await api('/stats/cumulative');
      state.cumulative = {
        mappedAlertCount: data.mappedAlertCount ?? 0,
        attackChainCount: data.attackChainCount ?? 0
      };
    } catch (_) {
      state.cumulative = { mappedAlertCount: 0, attackChainCount: 0 };
    }
    renderTopStats();
  }

  /** 映射方式英文码 → 中文（兼容旧响应无 methodLabel） */
  function methodLabelOf(method) {
    const map = {
      explicit: '文中标明',
      rule: '类型规则',
      heuristic: '关键词启发',
      fallback: '默认设定'
    };
    return map[method] || method || '';
  }

  function qualityClass(q) {
    return `q-${q || 'poor'}`;
  }

  function renderCoverage(coverage) {
    state.coverage = coverage;
    els.coverageMatrix.innerHTML = '';
    const matrix = (coverage && coverage.matrix) || [];
    if (!matrix.length) {
      els.coverageMatrix.innerHTML = '<div class="empty-state">暂无覆盖数据</div>';
      return;
    }
    const frag = document.createDocumentFragment();
    for (const cell of matrix) {
      const div = document.createElement('div');
      const covered = !!cell.covered;
      div.className = `matrix-cell${covered ? ' covered' : ' uncovered'}`;
      const techText = (cell.techniques || [])
        .slice(0, 3)
        .map((t) => `${t.id}×${t.count}`)
        .join(' · ');
      div.innerHTML = `
        <div class="status-tag">${covered ? '已覆盖' : '未覆盖'}</div>
        <div class="tid">${escapeHtml(cell.tacticId)}</div>
        <div class="tname">${escapeHtml(cell.tacticName)}</div>
        <div class="ten">${escapeHtml(cell.tacticNameEn)}</div>
        <div class="count">${cell.alertCount || 0}<span class="count-label">条告警</span></div>
        <div class="techs">${escapeHtml(covered ? techText || '—' : '本批次未命中')}</div>
      `;
      frag.appendChild(div);
    }
    els.coverageMatrix.appendChild(frag);
  }

  /** 统一链路显示名：攻击链路（batchId） */
  function normalizeChainName(chain, index, total) {
    const id = state.batchId || chain?.batchId || 'unknown';
    const n = total || 1;
    if (n > 1) return `攻击链路（${id}#${index + 1}）`;
    return `攻击链路（${id}）`;
  }

  function renderChains(chains) {
    const list = chains || [];
    state.chains = list.map((c, i) => ({
      ...c,
      batchId: state.batchId || c.batchId,
      name: normalizeChainName(c, i, list.length)
    }));
    els.chainList.innerHTML = '';
    if (!state.chains.length) {
      els.chainList.innerHTML =
        '<div class="empty-state">执行「构建攻击链路」后在此展示</div>';
      return;
    }
    const frag = document.createDocumentFragment();
    state.chains.forEach((chain, idx) => {
      const card = document.createElement('article');
      card.className = 'chain-card';
      card.style.animationDelay = `${idx * 0.05}s`;

      const stages = chain.stages || [];
      const stagesHtml = stages
        .map((s, si) => {
          const items = (s.alerts || [])
            .slice(0, 4)
            .map(
              (a) =>
                `<li>${escapeHtml(a.mapping?.primary || a.mapping?.tacticId || '')} ${escapeHtml(a.title || '')}</li>`
            )
            .join('');
          const node = `
            <div class="stage-node">
              <div class="sn-id">${escapeHtml(s.tacticId)}</div>
              <div class="sn-title">${escapeHtml(s.tacticName)} <span style="color:var(--muted);font-weight:400">(${escapeHtml(s.tacticNameEn || '')})</span></div>
              <ul>${items || '<li>无告警</li>'}</ul>
            </div>`;
          const arrow =
            si < stages.length - 1
              ? `<span class="stage-arrow" title="战术执行方向" aria-hidden="true">→</span>`
              : '';
          return node + arrow;
        })
        .join('');

      const timelineHtml = (chain.timeline || [])
        .map(
          (t) => `
          <div class="timeline-item">
            <div class="t-time">${escapeHtml(t.stepLabel || t.timeDisplay || fmtTime(t))}</div>
            <div class="t-body">
              <div>${escapeHtml(t.title || t.attackType || '')}</div>
              <div class="t-tech">${escapeHtml(
                (Array.isArray(t.techniques) && t.techniques.length
                  ? t.techniques.map((x) => x.id || x).join(', ')
                  : t.technique) || '（仅战术）'
              )} · ${escapeHtml(
                (Array.isArray(t.tacticIds) && t.tacticIds.length
                  ? t.tacticIds.join(', ')
                  : t.tacticId) || ''
              )} · conf ${t.confidence != null ? Number(t.confidence).toFixed(2) : '-'}</div>
            </div>
          </div>`
        )
        .join('');

      const rangeLabel =
        chain.timeMode === 'steps'
          ? escapeHtml(chain.durationHuman || '无明确时序（按攻击步骤）')
          : `${fmtTime(chain.startTime)} → ${fmtTime(chain.endTime)}`;

      card.innerHTML = `
        <div class="chain-head">
          <div>
            <h3>${escapeHtml(chain.name || `攻击链路${idx + 1}`)}</h3>
            <div class="chain-meta" style="margin-top:0.35rem">
              <span>${rangeLabel}</span>
            </div>
          </div>
          <div class="chain-meta">
            <span>告警 ${chain.alertCount}</span>
            <span>${escapeHtml(chain.durationHuman || '-')}</span>
            <span>技术 ${((chain.techniques || []).length)}</span>
            <span>战术 ${(chain.coveredTactics || []).length}</span>
            <span class="complexity ${escapeHtml(chain.complexityLevel || 'low')}">复杂度 ${chain.complexityScore} (${escapeHtml(chain.complexityLevel || '-')})</span>
          </div>
        </div>
        <div class="stage-flow">${stagesHtml}</div>
        <div class="timeline">${timelineHtml}</div>
      `;
      frag.appendChild(card);
    });
    els.chainList.appendChild(frag);
  }

  function escapeHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function applyResult(data, { keepChains } = {}) {
    if (data.contentHash) {
      // 相同内容指纹时保留/采用服务端复用的 batchId
      state.contentHash = data.contentHash;
    }
    if (data.batchId) {
      state.batchId = data.batchId;
      els.batchIdLabel.textContent = `batchId: ${data.batchId}`;
    }
    if (data.mapped) {
      renderMapped(data.mapped);
      state.sessionMapped = true;
    }
    if (data.coverage) {
      state.coverage = data.coverage;
      renderCoverage(data.coverage);
    }
    if (data.stats) state.stats = data.stats;
    if (data.chains) {
      renderChains(data.chains);
      if (data.chains.length) state.sessionBuilt = true;
    } else if (!keepChains) {
      renderChains([]);
    }
    if (data.mapped || data.chains || data.stats) {
      state.hasComputedBatch = true;
    }
    renderTopStats();
    updatePersistButtons();
  }

  /** 清除已选文件（含 input 与状态），便于改用文本或重新上传 */
  function clearFile() {
    state.file = null;
    state.sourceExplicit = false;
    if (els.fileInput) els.fileInput.value = '';
    if (els.fileName) els.fileName.textContent = '未选择文件';
    if (els.btnClearFile) els.btnClearFile.hidden = true;
    els.fileName?.parentElement?.classList.remove('has-file');
    if (state.preferredSource === 'file') state.preferredSource = null;
    syncInputSourceUI();
  }

  function setSelectedFile(f) {
    state.file = f || null;
    if (els.fileName) els.fileName.textContent = f ? f.name : '未选择文件';
    if (els.btnClearFile) els.btnClearFile.hidden = !f;
    els.fileName?.parentElement?.classList.toggle('has-file', !!f);
    if (f) {
      const text = els.alertText.value.trim();
      // 与文本并存时必须重新确认，不沿用旧选择
      state.sourceExplicit = false;
      state.preferredSource = text ? null : 'file';
    } else if (state.preferredSource === 'file') {
      state.preferredSource = null;
      state.sourceExplicit = false;
    }
    syncInputSourceUI();
  }

  function getInputSnapshot() {
    const text = els.alertText.value.trim();
    return {
      file: state.file,
      text,
      hasFile: !!state.file,
      hasText: !!text
    };
  }

  /** 根据当前输入刷新「本次将使用」提示与高亮 */
  function syncInputSourceUI() {
    const { hasFile, hasText, file, text } = getInputSnapshot();
    const bar = els.inputSourceBar;
    const status = els.inputSourceStatus;
    const pick = els.inputSourcePick;
    if (!bar || !status) return;

    els.fileCol?.classList.remove('is-active', 'is-dimmed');
    els.textCol?.classList.remove('is-active', 'is-dimmed');

    if (hasFile && hasText) {
      // 从「仅一侧」变为「两侧」时，作废自动选择，必须显式确认
      if (!state.sourceExplicit) state.preferredSource = null;
      bar.dataset.state = 'conflict';
      pick.hidden = false;
      const choice = state.preferredSource;
      if (els.sourceFile) els.sourceFile.checked = choice === 'file';
      if (els.sourceText) els.sourceText.checked = choice === 'text';
      if (choice === 'file') {
        status.textContent = `已选择使用文件「${file.name}」（文本框内容本次不参与映射）`;
        els.fileCol?.classList.add('is-active');
        els.textCol?.classList.add('is-dimmed');
      } else if (choice === 'text') {
        status.textContent = `已选择使用文本框（${text.length} 字）（已选文件本次不参与映射）`;
        els.textCol?.classList.add('is-active');
        els.fileCol?.classList.add('is-dimmed');
      } else {
        status.textContent = '检测到文件与文本同时存在，请选择本次映射使用哪一项，或先清除其中一侧';
      }
      return;
    }

    pick.hidden = true;
    state.sourceExplicit = false;
    if (els.sourceFile) els.sourceFile.checked = false;
    if (els.sourceText) els.sourceText.checked = false;

    if (hasFile) {
      state.preferredSource = 'file';
      bar.dataset.state = 'ready';
      status.textContent = `本次将使用文件：「${file.name}」`;
      els.fileCol?.classList.add('is-active');
      return;
    }
    if (hasText) {
      state.preferredSource = 'text';
      bar.dataset.state = 'ready';
      status.textContent = `本次将使用文本框内容（${text.length} 字）`;
      els.textCol?.classList.add('is-active');
      return;
    }

    state.preferredSource = null;
    bar.dataset.state = 'empty';
    status.textContent = '请上传文件或粘贴告警文本';
  }

  /** 弹层确认数据源；返回 'file' | 'text' | null */
  function askSourceModal() {
    return new Promise((resolve) => {
      const modal = els.sourceModal;
      if (!modal) {
        resolve(null);
        return;
      }
      const { file, text } = getInputSnapshot();
      if (els.sourceModalMsg) {
        els.sourceModalMsg.textContent =
          `当前同时存在已选文件「${file?.name || ''}」与文本框内容（${text.length} 字）。请确认本次映射使用哪一项。`;
      }
      if (els.sourceModalFile) {
        els.sourceModalFile.textContent = `使用文件「${file?.name || ''}」`;
      }

      const finish = (value) => {
        modal.hidden = true;
        modal.removeEventListener('click', onBackdrop);
        els.sourceModalClose?.removeEventListener('click', onCancel);
        els.sourceModalFile?.removeEventListener('click', onFile);
        els.sourceModalText?.removeEventListener('click', onText);
        document.removeEventListener('keydown', onKey);
        resolve(value);
      };
      const onCancel = () => finish(null);
      const onFile = () => finish('file');
      const onText = () => finish('text');
      const onBackdrop = (e) => {
        if (e.target === modal) finish(null);
      };
      const onKey = (e) => {
        if (e.key === 'Escape') finish(null);
      };

      els.sourceModalClose?.addEventListener('click', onCancel);
      els.sourceModalFile?.addEventListener('click', onFile);
      els.sourceModalText?.addEventListener('click', onText);
      modal.addEventListener('click', onBackdrop);
      document.addEventListener('keydown', onKey);
      modal.hidden = false;
    });
  }

  /**
   * 解析本次映射数据源：仅一侧时自动选用；两侧都有时用用户已选，否则弹窗确认。
   */
  async function resolveInputSource() {
    const { hasFile, hasText } = getInputSnapshot();
    if (!hasFile && !hasText) return null;
    if (hasFile && !hasText) return 'file';
    if (!hasFile && hasText) return 'text';
    if (state.preferredSource === 'file' || state.preferredSource === 'text') {
      return state.preferredSource;
    }
    const chosen = await askSourceModal();
    if (chosen) {
      state.preferredSource = chosen;
      state.sourceExplicit = true;
      syncInputSourceUI();
    }
    return chosen;
  }

  /** 按已确认数据源组装 FormData（只发送一侧） */
  function buildAlertFormData(source) {
    const { file, text } = getInputSnapshot();
    const fd = new FormData();
    if (source === 'file') {
      if (!file) return { fd: null, ok: false };
      fd.append('file', file);
      return { fd, ok: true, label: `文件「${file.name}」` };
    }
    if (source === 'text') {
      if (!text) return { fd: null, ok: false };
      fd.append('text', text);
      return { fd, ok: true, label: `文本框（${text.length} 字）` };
    }
    return { fd: null, ok: false };
  }

  async function doMap() {
    const source = await resolveInputSource();
    if (!source) {
      const { hasFile, hasText } = getInputSnapshot();
      if (!hasFile && !hasText) alert('请先上传文件或输入告警文本');
      return;
    }
    setBusy(true);
    try {
      const { fd, ok, label } = buildAlertFormData(source);
      if (!ok) {
        alert('请先上传文件或输入告警文本');
        return;
      }
      const data = await api('/mapping/batch', { method: 'POST', body: fd });
      applyResult(data);
      els.batchHint.textContent = `批量映射完成（数据源：${label}）：${data.mapped?.length || 0} 条 · 准确率 ${data.stats?.mappingAccuracyPercent || '-'}`;
    } catch (e) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function doBuild() {
    if (!state.mapped.length && !state.batchId) {
      alert('请先执行批量映射');
      return;
    }
    setBusy(true);
    try {
      const data = await api('/chains/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          batchId: state.batchId,
          contentHash: state.contentHash,
          mapped: state.mapped
        })
      });
      applyResult(data, { keepChains: true });
      els.batchHint.textContent = `攻击链路构建完成：${data.chains?.length || 0} 条链路 · 覆盖率 ${data.stats?.tacticCoveragePercent || '-'}`;
    } catch (e) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function doPipeline() {
    const source = await resolveInputSource();
    if (!source) {
      const { hasFile, hasText } = getInputSnapshot();
      if (!hasFile && !hasText) alert('请先上传文件或输入告警文本');
      return;
    }
    setBusy(true);
    try {
      const { fd, ok, label } = buildAlertFormData(source);
      if (!ok) {
        alert('请先上传文件或输入告警文本');
        return;
      }
      const data = await api('/pipeline', { method: 'POST', body: fd });
      applyResult(data);
      els.batchHint.textContent = `一键完成（数据源：${label}）：映射 ${data.mapped?.length || 0} · 链路 ${data.chains?.length || 0}`;
    } catch (e) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  /** 从 Mongo samplealerts 选取示例填入文本框 */
  const samplePickerState = { selectedId: null, cache: [], count: null };

  function setSamplePickerButtonLabel(count) {
    if (!els.btnPickDbSample) return;
    if (count == null || !Number.isFinite(Number(count))) {
      els.btnPickDbSample.textContent = '（可选）内置告警样本库（… 条）';
      return;
    }
    const n = Math.max(0, Number(count));
    samplePickerState.count = n;
    els.btnPickDbSample.textContent = `（可选）内置告警样本库（${n} 条）`;
  }

  async function refreshSampleCount() {
    if (!els.btnPickDbSample) return;
    try {
      const data = await api('/samples');
      const n = data.count ?? (data.samples || []).length;
      setSamplePickerButtonLabel(n);
    } catch (_) {
      setSamplePickerButtonLabel(state.mongoOk === false ? 0 : null);
    }
  }

  function closeSampleModal() {
    if (els.sampleModal) els.sampleModal.hidden = true;
  }

  function applySampleContent(content, name) {
    els.alertText.value = content;
    clearFile();
    state.preferredSource = 'text';
    state.sourceExplicit = false;
    syncInputSourceUI();
    if (els.batchHint) {
      els.batchHint.textContent = `已从内置告警样本库填入：「${name || '未命名'}」`;
    }
  }

  async function openSampleModal() {
    const modal = els.sampleModal;
    if (!modal) return;
    samplePickerState.selectedId = null;
    if (els.sampleModalApply) els.sampleModalApply.disabled = true;
    if (els.samplePreview) {
      els.samplePreview.hidden = true;
      els.samplePreview.textContent = '';
    }
    if (els.sampleList) els.sampleList.innerHTML = '<div class="empty-state">加载中…</div>';
    if (els.sampleModalHint) {
      els.sampleModalHint.textContent = '正在从集合 samplealerts 读取告警…';
    }
    modal.hidden = false;

    try {
      const data = await api('/samples');
      const samples = data.samples || [];
      samplePickerState.cache = samples;
      setSamplePickerButtonLabel(data.count ?? samples.length);
      if (!samples.length) {
        if (els.sampleList) {
          els.sampleList.innerHTML =
            '<div class="empty-state">库中暂无示例。请先运行 backend：npm run init-db</div>';
        }
        if (els.sampleModalHint) {
          els.sampleModalHint.textContent =
            '未读到示例告警。确认 Mongo 已连，并执行 npm run init-db 写入 samplealerts。';
        }
        return;
      }
      if (els.sampleModalHint) {
        els.sampleModalHint.textContent = `共 ${samples.length} 条库内示例，点击选中后可预览并填入文本框。`;
      }
      if (els.sampleList) {
        els.sampleList.innerHTML = '';
        samples.forEach((s) => {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'sample-item';
          btn.dataset.id = s.id;
          btn.innerHTML = `<span class="sample-item-title">${escapeHtml(s.name)}</span><span class="sample-item-desc">${escapeHtml(s.description || s.format || '')}</span>`;
          btn.addEventListener('click', () => selectSampleItem(s.id));
          els.sampleList.appendChild(btn);
        });
      }
    } catch (e) {
      if (els.sampleList) {
        els.sampleList.innerHTML = `<div class="empty-state">${escapeHtml(e.message || '读取失败')}</div>`;
      }
      if (els.sampleModalHint) {
        els.sampleModalHint.textContent = e.message || '读取库内示例失败';
      }
    }
  }

  async function selectSampleItem(id) {
    samplePickerState.selectedId = id;
    els.sampleList?.querySelectorAll('.sample-item').forEach((el) => {
      el.classList.toggle('is-selected', el.dataset.id === id);
    });
    if (els.sampleModalApply) els.sampleModalApply.disabled = true;
    try {
      const detail = await api(`/samples/${encodeURIComponent(id)}`);
      if (els.samplePreview) {
        els.samplePreview.hidden = false;
        els.samplePreview.textContent = detail.content || '';
      }
      samplePickerState.cache = samplePickerState.cache.map((s) =>
        s.id === id ? { ...s, content: detail.content, name: detail.name } : s
      );
      if (els.sampleModalApply) els.sampleModalApply.disabled = !detail.content;
    } catch (e) {
      if (els.samplePreview) {
        els.samplePreview.hidden = false;
        els.samplePreview.textContent = e.message || '加载失败';
      }
    }
  }

  function applySelectedSample() {
    const id = samplePickerState.selectedId;
    const hit = samplePickerState.cache.find((s) => s.id === id);
    if (!hit || !hit.content) {
      alert('请先选择一条示例告警');
      return;
    }
    applySampleContent(hit.content, hit.name);
    closeSampleModal();
  }

  function bindSampleModal() {
    els.btnPickDbSample?.addEventListener('click', openSampleModal);
    els.sampleModalClose?.addEventListener('click', closeSampleModal);
    els.sampleModalApply?.addEventListener('click', applySelectedSample);
    els.sampleModal?.addEventListener('click', (e) => {
      if (e.target === els.sampleModal) closeSampleModal();
    });
  }

  function bindFile() {
    els.fileInput.addEventListener('change', () => {
      const f = els.fileInput.files && els.fileInput.files[0];
      setSelectedFile(f);
    });
    els.btnClearFile?.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      clearFile();
    });
    els.alertText?.addEventListener('input', () => {
      const { hasFile, hasText } = getInputSnapshot();
      if (hasFile && hasText && !state.sourceExplicit) {
        state.preferredSource = null;
      } else if (!hasText && state.preferredSource === 'text') {
        state.preferredSource = null;
        state.sourceExplicit = false;
      }
      syncInputSourceUI();
    });
    els.sourceFile?.addEventListener('change', () => {
      if (els.sourceFile.checked) {
        state.preferredSource = 'file';
        state.sourceExplicit = true;
        syncInputSourceUI();
      }
    });
    els.sourceText?.addEventListener('change', () => {
      if (els.sourceText.checked) {
        state.preferredSource = 'text';
        state.sourceExplicit = true;
        syncInputSourceUI();
      }
    });
    ['dragenter', 'dragover'].forEach((ev) => {
      els.fileDrop.addEventListener(ev, (e) => {
        e.preventDefault();
        els.fileDrop.classList.add('dragover');
      });
    });
    ['dragleave', 'drop'].forEach((ev) => {
      els.fileDrop.addEventListener(ev, (e) => {
        e.preventDefault();
        els.fileDrop.classList.remove('dragover');
      });
    });
    els.fileDrop.addEventListener('drop', (e) => {
      const f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) {
        try {
          els.fileInput.files = e.dataTransfer.files;
        } catch (_) {
          /* 部分浏览器不允许赋值 FileList，仍用 state.file */
        }
        setSelectedFile(f);
      }
    });
  }

  async function init() {
    bindFile();
    bindFilters();
    bindDescModal();
    bindSampleModal();
    syncInputSourceUI();
    els.btnMap.addEventListener('click', doMap);
    els.btnBuild.addEventListener('click', doBuild);
    els.btnPipeline.addEventListener('click', doPipeline);
    els.btnSaveAlerts?.addEventListener('click', () => doPersist('alerts'));
    els.btnSaveChains?.addEventListener('click', () => doPersist('chains'));
    els.btnSaveStats?.addEventListener('click', () => doPersist('stats'));
    updatePersistButtons();

    try {
      const health = await api('/health');
      state.mongoOk = !!health.mongo;
      const mongoLabel = health.mongo ? 'Mongo 已连' : 'Mongo 未连';
      // els.apiStatus.textContent = `API 正常 · ${health.techniques || 0} 技术 · ${mongoLabel}`;
      els.apiStatus.textContent = `API 正常 · ${mongoLabel}`;
      els.apiStatus.classList.add('ok');
    } catch (e) {
      els.apiStatus.textContent = 'API 不可用';
      els.apiStatus.classList.add('err');
      state.mongoOk = false;
    }
    updatePersistButtons();

    // 打开/刷新：本会话从零开始；库内累计从 Mongo 读取
    state.sessionMapped = false;
    state.sessionBuilt = false;
    state.stats = null;
    await refreshCumulativeStats();
    await refreshSampleCount();

    // Preload empty matrix from tactics endpoint
    try {
      const t = await api('/attck/tactics');
      if (t.tactics) {
        renderCoverage({
          matrix: t.tactics.map((x) => ({
            tacticId: x.id,
            tacticName: x.name,
            tacticNameEn: x.nameEn,
            covered: false,
            alertCount: 0,
            techniques: []
          }))
        });
      }
    } catch (_) {
      /* ignore */
    }
  }

  init();
})();
