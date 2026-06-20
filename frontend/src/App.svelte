<script lang="ts">
  import { onMount } from 'svelte'
  import { DeleteReport, ListReports, SaveReport, StorePath } from '../wailsjs/go/main/App.js'

  type Report = {
    id: string
    title: string
    program: string
    asset: string
    severity: Severity
    status: Status
    bounty: string
    submittedAt: string
    dueAt: string
    cve: string
    tags: string[]
    summary: string
    impact: string
    steps: string
    evidence: string
    notes: string
    createdAt: string
    updatedAt: string
  }

  type ReportDraft = Omit<Report, 'createdAt' | 'updatedAt'>
  type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  type Status = 'Draft' | 'Submitted' | 'Triaged' | 'Resolved' | 'Duplicate' | 'Rejected' | 'Paid'

  const severities: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
  const statuses: Status[] = ['Draft', 'Submitted', 'Triaged', 'Resolved', 'Duplicate', 'Rejected', 'Paid']

  const statusLabels: Record<Status, string> = {
    Draft: '下書き',
    Submitted: '提出済み',
    Triaged: '確認中',
    Resolved: '修正済み',
    Duplicate: '重複',
    Rejected: '却下',
    Paid: '支払済み'
  }

  const severityLabels: Record<Severity, string> = {
    Critical: 'Critical',
    High: 'High',
    Medium: 'Medium',
    Low: 'Low',
    Info: 'Info'
  }

  let reports: Report[] = []
  let selectedId = ''
  let search = ''
  let statusFilter: 'All' | Status = 'All'
  let severityFilter: 'All' | Severity = 'All'
  let draft: ReportDraft = emptyDraft()
  let tagsText = ''
  let storePath = ''
  let loading = true
  let saving = false
  let errorMessage = ''

  $: filteredReports = reports.filter(matchesFilters)
  $: selectedReport = reports.find((report) => report.id === selectedId)
  $: metrics = buildMetrics(reports)

  onMount(async () => {
    await loadReports()
  })

  function emptyDraft(): ReportDraft {
    return {
      id: '',
      title: '',
      program: '',
      asset: '',
      severity: 'Medium',
      status: 'Draft',
      bounty: '',
      submittedAt: '',
      dueAt: '',
      cve: '',
      tags: [],
      summary: '',
      impact: '',
      steps: '',
      evidence: '',
      notes: ''
    }
  }

  async function loadReports() {
    loading = true
    errorMessage = ''

    try {
      reports = (await ListReports()).map(normalizeReport)
      storePath = await StorePath()
      if (reports.length > 0) {
        selectReport(reports[0])
      } else {
        createReport()
      }
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : String(error)
    } finally {
      loading = false
    }
  }

  function createReport() {
    selectedId = ''
    draft = emptyDraft()
    tagsText = ''
  }

  function selectReport(report: Report) {
    selectedId = report.id
    draft = {
      id: report.id,
      title: report.title,
      program: report.program,
      asset: report.asset,
      severity: report.severity,
      status: report.status,
      bounty: report.bounty,
      submittedAt: report.submittedAt,
      dueAt: report.dueAt,
      cve: report.cve,
      tags: report.tags,
      summary: report.summary,
      impact: report.impact,
      steps: report.steps,
      evidence: report.evidence,
      notes: report.notes
    }
    tagsText = report.tags.join(', ')
  }

  async function saveCurrentReport() {
    saving = true
    errorMessage = ''

    try {
      const saved = normalizeReport(await SaveReport({
        ...draft,
        tags: tagsText.split(',').map((tag) => tag.trim()).filter(Boolean)
      }))
      const index = reports.findIndex((report) => report.id === saved.id)
      if (index >= 0) {
        reports = reports.map((report) => report.id === saved.id ? saved : report)
      } else {
        reports = [saved, ...reports]
      }
      selectReport(saved)
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : String(error)
    } finally {
      saving = false
    }
  }

  async function deleteCurrentReport() {
    if (!selectedId || !confirm('この報告を削除しますか？')) {
      return
    }

    try {
      await DeleteReport(selectedId)
      reports = reports.filter((report) => report.id !== selectedId)
      if (reports.length > 0) {
        selectReport(reports[0])
      } else {
        createReport()
      }
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : String(error)
    }
  }

  function matchesFilters(report: Report) {
    const query = search.trim().toLowerCase()
    const searchable = [
      report.title,
      report.program,
      report.asset,
      report.cve,
      report.summary,
      report.tags.join(' ')
    ].join(' ').toLowerCase()

    return (!query || searchable.includes(query))
      && (statusFilter === 'All' || report.status === statusFilter)
      && (severityFilter === 'All' || report.severity === severityFilter)
  }

  function normalizeReport(source: unknown): Report {
    const report = source as Record<string, unknown>

    return {
      id: String(report.id ?? ''),
      title: String(report.title ?? ''),
      program: String(report.program ?? ''),
      asset: String(report.asset ?? ''),
      severity: normalizeSeverity(String(report.severity ?? 'Medium')),
      status: normalizeStatus(String(report.status ?? 'Draft')),
      bounty: String(report.bounty ?? ''),
      submittedAt: String(report.submittedAt ?? ''),
      dueAt: String(report.dueAt ?? ''),
      cve: String(report.cve ?? ''),
      tags: Array.isArray(report.tags) ? report.tags.map((tag) => String(tag)) : [],
      summary: String(report.summary ?? ''),
      impact: String(report.impact ?? ''),
      steps: String(report.steps ?? ''),
      evidence: String(report.evidence ?? ''),
      notes: String(report.notes ?? ''),
      createdAt: String(report.createdAt ?? ''),
      updatedAt: String(report.updatedAt ?? '')
    }
  }

  function normalizeSeverity(value: string): Severity {
    return severities.includes(value as Severity) ? value as Severity : 'Medium'
  }

  function normalizeStatus(value: string): Status {
    return statuses.includes(value as Status) ? value as Status : 'Draft'
  }

  function buildMetrics(source: Report[]) {
    const open = source.filter((report) => !['Resolved', 'Rejected', 'Duplicate', 'Paid'].includes(report.status)).length
    const triaged = source.filter((report) => report.status === 'Triaged').length
    const paid = source.filter((report) => report.status === 'Paid').length
    const bountyTotal = source.reduce((sum, report) => sum + parseBounty(report.bounty), 0)
    return { open, triaged, paid, bountyTotal }
  }

  function parseBounty(value: string) {
    const amount = Number(value.replace(/[^0-9.]/g, ''))
    return Number.isFinite(amount) ? amount : 0
  }

  function isDueSoon(report: Report) {
    if (!report.dueAt || ['Resolved', 'Rejected', 'Duplicate', 'Paid'].includes(report.status)) {
      return false
    }

    const due = new Date(`${report.dueAt}T23:59:59`)
    const ms = due.getTime() - Date.now()
    return ms <= 1000 * 60 * 60 * 24 * 3
  }

  function formatDate(value: string) {
    if (!value) {
      return '未設定'
    }
    return new Intl.DateTimeFormat('ja-JP', { month: '2-digit', day: '2-digit' }).format(new Date(value))
  }
</script>

<main class="workspace">
  <aside class="sidebar">
    <div class="brand-row">
      <div>
        <p class="eyebrow">VulnDock</p>
        <h1>脆弱性報告</h1>
      </div>
      <button class="icon-button" type="button" title="新規報告" on:click={createReport}>+</button>
    </div>

    <div class="metrics-grid" aria-label="Report metrics">
      <div>
        <span>{reports.length}</span>
        <p>総件数</p>
      </div>
      <div>
        <span>{metrics.open}</span>
        <p>対応中</p>
      </div>
      <div>
        <span>{metrics.triaged}</span>
        <p>確認中</p>
      </div>
      <div>
        <span>${metrics.bountyTotal.toLocaleString()}</span>
        <p>報奨金</p>
      </div>
    </div>

    <div class="filter-panel">
      <input bind:value={search} placeholder="検索" type="search" aria-label="検索" />
      <select bind:value={statusFilter} aria-label="ステータス">
        <option value="All">すべての状態</option>
        {#each statuses as status}
          <option value={status}>{statusLabels[status]}</option>
        {/each}
      </select>
      <select bind:value={severityFilter} aria-label="重大度">
        <option value="All">すべての重大度</option>
        {#each severities as severity}
          <option value={severity}>{severityLabels[severity]}</option>
        {/each}
      </select>
    </div>

    <div class="report-list" aria-live="polite">
      {#if loading}
        <p class="empty-state">読み込み中...</p>
      {:else if filteredReports.length === 0}
        <p class="empty-state">一致する報告はありません。</p>
      {:else}
        {#each filteredReports as report}
          <button
            class:active={report.id === selectedId}
            class:due-soon={isDueSoon(report)}
            class="report-item"
            type="button"
            on:click={() => selectReport(report)}
          >
            <span class="item-topline">
              <strong>{report.title}</strong>
              <em class={`severity severity-${report.severity.toLowerCase()}`}>{report.severity}</em>
            </span>
            <span class="item-meta">{report.program || '未分類'} · {statusLabels[report.status]}</span>
            <span class="item-meta">{report.asset || '対象未設定'} · 期限 {formatDate(report.dueAt)}</span>
          </button>
        {/each}
      {/if}
    </div>
  </aside>

  <section class="editor">
    <header class="editor-header">
      <div>
        <p class="eyebrow">{selectedReport ? '編集中' : '新規作成'}</p>
        <input class="title-input" bind:value={draft.title} placeholder="報告タイトル" aria-label="報告タイトル" />
      </div>
      <div class="action-row">
        <button class="ghost-button" type="button" on:click={deleteCurrentReport} disabled={!selectedId}>削除</button>
        <button class="primary-button" type="button" on:click={saveCurrentReport} disabled={saving}>
          {saving ? '保存中...' : '保存'}
        </button>
      </div>
    </header>

    {#if errorMessage}
      <p class="error-banner">{errorMessage}</p>
    {/if}

    <div class="form-grid">
      <label>
        プログラム
        <input bind:value={draft.program} placeholder="HackerOne / Bugcrowd / 社内診断" />
      </label>
      <label>
        対象
        <input bind:value={draft.asset} placeholder="example.com / API endpoint / repository" />
      </label>
      <label>
        重大度
        <select bind:value={draft.severity}>
          {#each severities as severity}
            <option value={severity}>{severityLabels[severity]}</option>
          {/each}
        </select>
      </label>
      <label>
        ステータス
        <select bind:value={draft.status}>
          {#each statuses as status}
            <option value={status}>{statusLabels[status]}</option>
          {/each}
        </select>
      </label>
      <label>
        提出日
        <input bind:value={draft.submittedAt} type="date" />
      </label>
      <label>
        期限
        <input bind:value={draft.dueAt} type="date" />
      </label>
      <label>
        CVE / 参照ID
        <input bind:value={draft.cve} placeholder="CVE-2026-0000 / VD-001" />
      </label>
      <label>
        報奨金
        <input bind:value={draft.bounty} placeholder="$500" />
      </label>
      <label class="wide">
        タグ
        <input bind:value={tagsText} placeholder="xss, auth, api" />
      </label>
    </div>

    <div class="writing-grid">
      <label>
        概要
        <textarea bind:value={draft.summary} rows="5" placeholder="脆弱性の要点"></textarea>
      </label>
      <label>
        影響
        <textarea bind:value={draft.impact} rows="5" placeholder="攻撃者ができること、被害範囲、前提条件"></textarea>
      </label>
      <label>
        再現手順
        <textarea bind:value={draft.steps} rows="8" placeholder="1. ..."></textarea>
      </label>
      <label>
        証跡リンク / 添付メモ
        <textarea bind:value={draft.evidence} rows="8" placeholder="動画、スクリーンショット、Burp history の場所"></textarea>
      </label>
    </div>
  </section>

  <aside class="inspector">
    <section>
      <p class="eyebrow">状態</p>
      <div class="status-stack">
        {#each statuses as status}
          <button
            class:active={draft.status === status}
            class="status-pill"
            type="button"
            on:click={() => draft.status = status}
          >
            {statusLabels[status]}
          </button>
        {/each}
      </div>
    </section>

    <section>
      <p class="eyebrow">タグ</p>
      <div class="tag-cloud">
        {#each tagsText.split(',').map((tag) => tag.trim()).filter(Boolean) as tag}
          <span>{tag}</span>
        {:else}
          <span class="muted">未設定</span>
        {/each}
      </div>
    </section>

    <section>
      <p class="eyebrow">メモ</p>
      <textarea class="notes" bind:value={draft.notes} rows="12" placeholder="ベンダー返信、追加検証、支払い状況など"></textarea>
    </section>

    <section class="storage-note">
      <p class="eyebrow">保存先</p>
      <code>{storePath || '未取得'}</code>
    </section>
  </aside>
</main>
