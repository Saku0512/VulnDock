<script lang="ts">
  import { onMount } from 'svelte'
  import { BrowserOpenURL } from '../wailsjs/runtime/runtime'
  import { DeleteReport, ListReports, SaveReport, StorePath } from '../wailsjs/go/main/App.js'
  import { main } from '../wailsjs/go/models'
  import { calculateCvss, inferCvssVersion } from './cvss'
  import logoUrl from './assets/images/logo.png'

  type Report = {
    id: string
    title: string
    program: string
    asset: string
    cvssVersion: CvssVersion
    cvssScore: string
    cvssVector: string
    status: Status
    submittedAt: string
    reportUrl: string
    tags: string[]
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
  type CvssVersion = '3.1' | '4.0'
  type CvssRating = 'Critical' | 'High' | 'Medium' | 'Low' | 'None'
  type Status = 'Draft' | 'Submitted' | 'Triaged' | 'Resolved' | 'Duplicate' | 'Rejected' | 'Paid'

  const cvssVersions: CvssVersion[] = ['3.1', '4.0']
  const cvssRatings: CvssRating[] = ['Critical', 'High', 'Medium', 'Low', 'None']
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

  const cvssRatingLabels: Record<CvssRating, string> = {
    Critical: 'Critical',
    High: 'High',
    Medium: 'Medium',
    Low: 'Low',
    None: 'None'
  }

  let reports = $state<Report[]>([])
  let selectedId = $state('')
  let search = $state('')
  let statusFilter = $state<'All' | Status>('All')
  let cvssRatingFilter = $state<'All' | CvssRating>('All')
  let draft = $state<ReportDraft>(emptyDraft())
  let tagsText = $state('')
  let storePath = $state('')
  let loading = $state(true)
  let saving = $state(false)
  let errorMessage = $state('')
  let pocInput = $state<HTMLInputElement>()

  let filteredReports = $derived(reports.filter(matchesFilters))
  let selectedReport = $derived(reports.find((report) => report.id === selectedId))
  let metrics = $derived(buildMetrics(reports))

  $effect(() => {
    syncCvssFromVector(draft.cvssVector)
  })

  onMount(async () => {
    await loadReports()
  })

  function emptyDraft(): ReportDraft {
    return {
      id: '',
      title: '',
      program: '',
      asset: '',
      cvssVersion: '3.1',
      cvssScore: '',
      cvssVector: '',
      status: 'Draft',
      submittedAt: '',
      reportUrl: '',
      tags: [],
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
      cvssVersion: report.cvssVersion,
      cvssScore: report.cvssScore,
      cvssVector: report.cvssVector,
      status: report.status,
      submittedAt: report.submittedAt,
      reportUrl: report.reportUrl,
      tags: report.tags,
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
      report.cvssScore,
      report.cvssVector,
      report.reportUrl,
      report.pocFiles.map((file) => file.name).join(' '),
      report.tags.join(' ')
    ].join(' ').toLowerCase()

    return (!query || searchable.includes(query))
      && (statusFilter === 'All' || report.status === statusFilter)
      && (cvssRatingFilter === 'All' || cvssRating(report.cvssScore) === cvssRatingFilter)
  }

  function normalizeReport(source: unknown): Report {
    const report = source as Record<string, unknown>

    return {
      id: String(report.id ?? ''),
      title: String(report.title ?? ''),
      program: String(report.program ?? ''),
      asset: String(report.asset ?? ''),
      cvssVersion: normalizeCvssVersion(String(report.cvssVersion ?? '3.1')),
      cvssScore: normalizeCvssScore(String(report.cvssScore ?? legacySeverityScore(report.severity))),
      cvssVector: String(report.cvssVector ?? ''),
      status: normalizeStatus(String(report.status ?? 'Draft')),
      submittedAt: String(report.submittedAt ?? ''),
      reportUrl: String(report.reportUrl ?? ''),
      tags: Array.isArray(report.tags) ? report.tags.map((tag) => String(tag)) : [],
      pocFiles: normalizePocFiles(report.pocFiles),
      createdAt: String(report.createdAt ?? ''),
      updatedAt: String(report.updatedAt ?? '')
    }
  }

  function normalizeCvssVersion(value: string): CvssVersion {
    return cvssVersions.includes(value as CvssVersion) ? value as CvssVersion : '3.1'
  }

  function normalizeCvssScore(value: string) {
    value = value.trim()
    if (!value) {
      return ''
    }
    const score = Number(value)
    if (!Number.isFinite(score)) {
      return ''
    }
    return Math.min(10, Math.max(0, score)).toFixed(1)
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

  function cvssRating(scoreValue: string): CvssRating {
    const score = Number(scoreValue)
    if (!Number.isFinite(score) || score <= 0) {
      return 'None'
    }
    if (score >= 9) {
      return 'Critical'
    }
    if (score >= 7) {
      return 'High'
    }
    if (score >= 4) {
      return 'Medium'
    }
    return 'Low'
  }

  function cvssBadge(report: Report) {
    const rating = cvssRating(report.cvssScore)
    return report.cvssScore ? `${rating} ${report.cvssScore}` : 'CVSS未設定'
  }

  function cvssClass(report: Report) {
    return cvssRating(report.cvssScore).toLowerCase()
  }

  function legacySeverityScore(value: unknown) {
    switch (String(value ?? '').trim().toLowerCase()) {
      case 'critical':
        return '9.0'
      case 'high':
        return '7.0'
      case 'medium':
        return '4.0'
      case 'low':
        return '0.1'
      case 'info':
      case 'none':
        return '0.0'
      default:
        return ''
    }
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

  function openReportUrl() {
    const url = draft.reportUrl.trim()
    if (!url) {
      return
    }
    BrowserOpenURL(url)
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

  function syncCvssFromVector(vector: string) {
    const version = inferCvssVersion(vector)
    if (version && version !== draft.cvssVersion) {
      draft.cvssVersion = version
    }

    if (!vector.trim()) {
      draft.cvssScore = ''
      return
    }

    draft.cvssScore = calculateCvss(version || draft.cvssVersion, vector)
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
      <button class="icon-button" type="button" title="新規報告" onclick={createReport}>+</button>
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
      <select bind:value={cvssRatingFilter} aria-label="CVSS評価">
        <option value="All">すべてのCVSS評価</option>
        {#each cvssRatings as rating}
          <option value={rating}>{cvssRatingLabels[rating]}</option>
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
            onclick={() => selectReport(report)}
          >
            <span class="item-topline">
              <strong>{report.title}</strong>
              <em class={`severity severity-${cvssClass(report)}`}>{cvssBadge(report)}</em>
            </span>
            <span class="item-meta">{report.program || '未分類'} · {statusLabels[report.status]}</span>
            <span class="item-meta">{report.asset || '対象未設定'} · CVSS {report.cvssVersion} · PoC {report.pocFiles.length}件</span>
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
        <button class="ghost-button" type="button" onclick={deleteCurrentReport} disabled={!selectedId}>削除</button>
        <button class="primary-button" type="button" onclick={saveCurrentReport} disabled={saving}>
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
        CVSS
        <select bind:value={draft.cvssVersion}>
          {#each cvssVersions as version}
            <option value={version}>{version}</option>
          {/each}
        </select>
      </label>
      <label>
        CVSSスコア
        <input value={draft.cvssScore || '未計算'} readonly aria-label="CVSSスコア" />
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
      <div class="report-url-field">
        <label>
          報告先URL
          <input bind:value={draft.reportUrl} placeholder="https://hackerone.com/reports/..." type="url" />
        </label>
        <button class="ghost-button link-button" type="button" onclick={openReportUrl} disabled={!draft.reportUrl.trim()}>
          開く
        </button>
      </div>
      <label class="wide">
        CVSSベクター
        <input bind:value={draft.cvssVector} placeholder="CVSS:4.0/... または CVSS:3.1/..." />
      </label>
      <label class="wide">
        タグ
        <input bind:value={tagsText} placeholder="xss, auth, api" />
      </label>
    </div>

    <div class="writing-grid">
      <section class="poc-panel">
        <div class="poc-header">
          <p class="eyebrow">PoCファイル</p>
          <button class="ghost-button attach-button" type="button" onclick={() => pocInput?.click()}>添付</button>
        </div>
        <input
          bind:this={pocInput}
          class="hidden-file-input"
          type="file"
          multiple
          onchange={(event) => attachPocFiles(event.currentTarget.files)}
        />
        <div class="attachment-list">
          {#each draft.pocFiles as file, index}
            <div class="attachment-item">
              <div>
                <a href={file.data} download={file.name}>{file.name}</a>
                <span>{formatFileSize(file.size)}</span>
              </div>
              <button class="small-button" type="button" onclick={() => removePocFile(index)}>削除</button>
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
