<script lang="ts">
  import { onMount } from 'svelte'
  import { DeleteReport, ListReports, SaveReport, StorePath } from '../wailsjs/go/main/App.js'
  import { main } from '../wailsjs/go/models'
  import logoUrl from './assets/images/logo.png'

  type Report = {
    id: string
    title: string
    program: string
    asset: string
    severity: Severity
    status: Status
    submittedAt: string
    tags: string[]
    body: string
    pocFiles: PocFile[]
    createdAt: string
    updatedAt: string
  }

  type ReportDraft = Omit<Report, 'createdAt' | 'updatedAt'>
  type PocFile = {
    name: string
    type: string
    size: number
    data: string
  }
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
  let pocInput: HTMLInputElement

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
      submittedAt: '',
      tags: [],
      body: '',
      pocFiles: []
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
      submittedAt: report.submittedAt,
      tags: report.tags,
      body: report.body,
      pocFiles: report.pocFiles
    }
    tagsText = report.tags.join(', ')
  }

  async function saveCurrentReport() {
    saving = true
    errorMessage = ''

    try {
      const saved = normalizeReport(await SaveReport(new main.ReportDraft({
        ...draft,
        tags: tagsText.split(',').map((tag) => tag.trim()).filter(Boolean)
      })))
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
      report.body,
      report.pocFiles.map((file) => file.name).join(' '),
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
      submittedAt: String(report.submittedAt ?? ''),
      tags: Array.isArray(report.tags) ? report.tags.map((tag) => String(tag)) : [],
      body: String(report.body ?? buildLegacyBody(report)),
      pocFiles: normalizePocFiles(report.pocFiles),
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
    const attachments = source.reduce((sum, report) => sum + report.pocFiles.length, 0)
    return { open, triaged, paid, attachments }
  }

  function buildLegacyBody(report: Record<string, unknown>) {
    const sections = [
      ['概要', report.summary],
      ['影響', report.impact],
      ['再現手順', report.steps],
      ['証跡リンク / 添付メモ', report.evidence],
      ['メモ', report.notes]
    ]

    return sections
      .map(([title, value]) => [title, String(value ?? '').trim()])
      .filter(([, value]) => value)
      .map(([title, value]) => `## ${title}\n${value}`)
      .join('\n\n')
  }

  function normalizePocFiles(source: unknown): PocFile[] {
    if (!Array.isArray(source)) {
      return []
    }

    return source
      .map((file) => file as Record<string, unknown>)
      .map((file) => ({
        name: String(file.name ?? '').trim(),
        type: String(file.type ?? '').trim(),
        size: Number(file.size ?? 0),
        data: String(file.data ?? '').trim()
      }))
      .filter((file) => file.name && file.data)
  }

  async function attachPocFiles(files: FileList | null) {
    if (!files || files.length === 0) {
      return
    }

    const attachments = await Promise.all(Array.from(files).map(readPocFile))
    draft.pocFiles = [...draft.pocFiles, ...attachments]
    if (pocInput) {
      pocInput.value = ''
    }
  }

  function readPocFile(file: File): Promise<PocFile> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve({
        name: file.name,
        type: file.type,
        size: file.size,
        data: String(reader.result ?? '')
      })
      reader.onerror = () => reject(reader.error)
      reader.readAsDataURL(file)
    })
  }

  function removePocFile(index: number) {
    draft.pocFiles = draft.pocFiles.filter((_, fileIndex) => fileIndex !== index)
  }

  function formatFileSize(size: number) {
    if (!Number.isFinite(size) || size <= 0) {
      return '0 B'
    }
    if (size < 1024) {
      return `${size} B`
    }
    if (size < 1024 * 1024) {
      return `${(size / 1024).toFixed(1)} KB`
    }
    return `${(size / 1024 / 1024).toFixed(1)} MB`
  }
</script>

<main class="workspace">
  <aside class="sidebar">
    <div class="brand-row">
      <div class="brand-mark">
        <img src={logoUrl} alt="" />
        <div>
          <p class="eyebrow">VulnDock</p>
          <h1>脆弱性報告</h1>
        </div>
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
        <span>{metrics.attachments}</span>
        <p>PoC添付</p>
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
            class="report-item"
            type="button"
            on:click={() => selectReport(report)}
          >
            <span class="item-topline">
              <strong>{report.title}</strong>
              <em class={`severity severity-${report.severity.toLowerCase()}`}>{report.severity}</em>
            </span>
            <span class="item-meta">{report.program || '未分類'} · {statusLabels[report.status]}</span>
            <span class="item-meta">{report.asset || '対象未設定'} · PoC {report.pocFiles.length}件</span>
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
      <label class="wide">
        タグ
        <input bind:value={tagsText} placeholder="xss, auth, api" />
      </label>
    </div>

    <div class="writing-grid">
      <label class="wide writing-main">
        レポート本文
        <textarea bind:value={draft.body} rows="18" placeholder="概要、影響、再現手順、証跡リンク、添付メモなど"></textarea>
      </label>

      <section class="poc-panel">
        <div class="poc-header">
          <p class="eyebrow">PoCファイル</p>
          <button class="ghost-button attach-button" type="button" on:click={() => pocInput?.click()}>添付</button>
        </div>
        <input
          bind:this={pocInput}
          class="hidden-file-input"
          type="file"
          multiple
          on:change={(event) => attachPocFiles(event.currentTarget.files)}
        />
        <div class="attachment-list">
          {#each draft.pocFiles as file, index}
            <div class="attachment-item">
              <div>
                <a href={file.data} download={file.name}>{file.name}</a>
                <span>{formatFileSize(file.size)}</span>
              </div>
              <button class="small-button" type="button" on:click={() => removePocFile(index)}>削除</button>
            </div>
          {:else}
            <p class="muted">未添付</p>
          {/each}
        </div>
      </section>

      <section class="storage-note">
        <p class="eyebrow">保存先</p>
        <code>{storePath || '未取得'}</code>
      </section>
    </div>
  </section>
</main>
