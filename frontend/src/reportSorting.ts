import { ListReports } from '../wailsjs/go/main/App.js'

export type ReportSortField =
  | 'updatedAt'
  | 'createdAt'
  | 'submittedAt'
  | 'nextActionAt'
  | 'cvssScore'
  | 'title'
  | 'program'

export type ReportSortDirection = 'asc' | 'desc'

export type ReportSortPreference = {
  field: ReportSortField
  direction: ReportSortDirection
}

export type SortableReport = {
  id: string
  title: string
  program: string
  asset: string
  status: string
  cvssVersion: string
  cvssScore: string
  cvssVector: string
  submittedAt: string
  nextActionAt: string
  createdAt: string
  updatedAt: string
  pocFiles: unknown[]
  rewardStatus: string
  rewardAmount: string
  rewardCurrency: string
  rewardPaidAt: string
  rewardNote: string
  memo: string
  reportUrl: string
  maintainerLog: string
  conversationLogs: unknown[]
  tags: string[]
}

export const DEFAULT_REPORT_SORT: ReportSortPreference = {
  field: 'updatedAt',
  direction: 'desc'
}

export const REPORT_SORT_OPTIONS: ReadonlyArray<{ value: ReportSortField; label: string }> = [
  { value: 'updatedAt', label: '更新日時' },
  { value: 'createdAt', label: '作成日時' },
  { value: 'submittedAt', label: '報告日' },
  { value: 'nextActionAt', label: '次アクション日時' },
  { value: 'cvssScore', label: 'CVSSスコア' },
  { value: 'title', label: 'タイトル' },
  { value: 'program', label: 'プログラム名' }
]

const storageKey = 'vulndock.report-sort.v1'
const controlsAttribute = 'data-report-sort-controls'
const collator = new Intl.Collator('ja', { numeric: true, sensitivity: 'base' })

const statusLabels: Record<string, string> = {
  Draft: '下書き',
  Submitted: '提出済み',
  Triaged: '確認中',
  Resolved: '修正済み',
  Published: '公開済み',
  Duplicate: '重複',
  Rejected: '却下',
  Paid: '支払済み'
}

const rewardStatusLabels: Record<string, string> = {
  Unknown: '未設定',
  Pending: '未払い',
  Paid: '支払済み',
  None: '報酬なし'
}

export function normalizeReportSortPreference(value: unknown): ReportSortPreference {
  const source = value && typeof value === 'object' ? value as Record<string, unknown> : {}
  const field = REPORT_SORT_OPTIONS.some((option) => option.value === source.field)
    ? source.field as ReportSortField
    : DEFAULT_REPORT_SORT.field
  const direction = source.direction === 'asc' || source.direction === 'desc'
    ? source.direction
    : DEFAULT_REPORT_SORT.direction
  return { field, direction }
}

export function sortReports<T extends Record<ReportSortField, string>>(
  reports: readonly T[],
  preference: ReportSortPreference
) {
  return reports
    .map((report, index) => ({ report, index }))
    .sort((left, right) => {
      const compared = compareSortValues(
        left.report[preference.field],
        right.report[preference.field],
        preference.field,
        preference.direction
      )
      return compared || left.index - right.index
    })
    .map(({ report }) => report)
}

export function reportMatchesSearch(report: SortableReport, queryValue: string) {
  const query = queryValue.trim().toLowerCase()
  if (!query) {
    return true
  }

  const searchable = [
    report.title,
    report.program,
    report.asset,
    report.cvssScore,
    report.cvssVector,
    report.nextActionAt,
    rewardSearchText(report),
    report.memo,
    report.reportUrl,
    report.maintainerLog,
    conversationLogsToText(report.conversationLogs),
    report.pocFiles.map((file) => String((file as Record<string, unknown>)?.name ?? '')).join(' '),
    report.tags.join(' ')
  ].join(' ').toLowerCase()

  return searchable.includes(query)
}

export function setupReportSorting(target: HTMLElement) {
  let reports: SortableReport[] = []
  let preference = loadPreference()
  let refreshQueued = false
  let refreshInFlight = false
  let refreshAgain = false

  const applyOrder = () => {
    const filterPanel = target.querySelector<HTMLElement>('.filter-panel')
    const reportList = target.querySelector<HTMLElement>('.report-list')
    if (!filterPanel || !reportList) {
      return
    }

    const controls = ensureSortControls(filterPanel, preference, (next) => {
      preference = next
      savePreference(preference)
      updateSortControls(controls, preference)
      applyOrder()
    })
    updateSortControls(controls, preference)

    const query = filterPanel.querySelector<HTMLInputElement>('input[type="search"]')?.value ?? ''
    const searchableReports = reports.filter((report) => reportMatchesSearch(report, query))
    const items = Array.from(reportList.querySelectorAll<HTMLElement>('.report-item'))
    const matchedReports = matchItemsToReports(items, searchableReports)
    const sorted = sortReports(
      matchedReports.filter((entry): entry is SortableReport => Boolean(entry)),
      preference
    )
    const ranks = new Map(sorted.map((report, index) => [report, index]))
    let fallbackRank = sorted.length

    for (let index = 0; index < items.length; index += 1) {
      const report = matchedReports[index]
      const rank = report ? ranks.get(report) : undefined
      items[index].style.order = String(rank ?? fallbackRank++)
    }
  }

  const refreshReports = async () => {
    if (refreshInFlight) {
      refreshAgain = true
      return
    }

    refreshInFlight = true
    try {
      reports = (await ListReports()).map(normalizeReport)
    } catch {
      // Keep the last successfully loaded snapshot.
    } finally {
      refreshInFlight = false
      applyOrder()
      if (refreshAgain) {
        refreshAgain = false
        void refreshReports()
      }
    }
  }

  const scheduleRefresh = () => {
    if (refreshQueued) {
      return
    }
    refreshQueued = true
    queueMicrotask(() => {
      refreshQueued = false
      void refreshReports()
    })
  }

  const observer = new MutationObserver(scheduleRefresh)
  observer.observe(target, { childList: true, subtree: true, characterData: true })
  scheduleRefresh()

  return () => observer.disconnect()
}

function compareSortValues(
  left: string,
  right: string,
  field: ReportSortField,
  direction: ReportSortDirection
) {
  const leftMissing = isMissing(left, field)
  const rightMissing = isMissing(right, field)
  if (leftMissing || rightMissing) {
    if (leftMissing && rightMissing) {
      return 0
    }
    return leftMissing ? 1 : -1
  }

  let compared = 0
  if (field === 'cvssScore') {
    compared = Number(left) - Number(right)
  } else if (isDateField(field)) {
    compared = timestamp(left) - timestamp(right)
  } else {
    compared = collator.compare(left.trim(), right.trim())
  }

  return direction === 'desc' ? -compared : compared
}

function isMissing(value: string, field: ReportSortField) {
  const trimmed = String(value ?? '').trim()
  if (!trimmed) {
    return true
  }
  if (field === 'cvssScore') {
    return !Number.isFinite(Number(trimmed))
  }
  if (isDateField(field)) {
    return !Number.isFinite(timestamp(trimmed))
  }
  return false
}

function isDateField(field: ReportSortField) {
  return field === 'updatedAt'
    || field === 'createdAt'
    || field === 'submittedAt'
    || field === 'nextActionAt'
}

function timestamp(value: string) {
  const dateOnly = value.match(/^(\d{4})-(\d{2})-(\d{2})$/)
  if (dateOnly) {
    return new Date(Number(dateOnly[1]), Number(dateOnly[2]) - 1, Number(dateOnly[3])).getTime()
  }
  return new Date(value).getTime()
}

function loadPreference() {
  try {
    return normalizeReportSortPreference(JSON.parse(localStorage.getItem(storageKey) || 'null'))
  } catch {
    return { ...DEFAULT_REPORT_SORT }
  }
}

function savePreference(preference: ReportSortPreference) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(preference))
  } catch {
    // Sorting still works when storage is unavailable.
  }
}

function ensureSortControls(
  filterPanel: HTMLElement,
  preference: ReportSortPreference,
  onChange: (next: ReportSortPreference) => void
) {
  const current = filterPanel.querySelector<HTMLElement>(`[${controlsAttribute}]`)
  if (current) {
    return current
  }

  const controls = document.createElement('div')
  controls.className = 'report-sort-controls'
  controls.setAttribute(controlsAttribute, '')

  const label = document.createElement('label')
  label.className = 'report-sort-field'
  label.textContent = '並び替え'

  const select = document.createElement('select')
  select.setAttribute('aria-label', '並び替え項目')
  for (const option of REPORT_SORT_OPTIONS) {
    const element = document.createElement('option')
    element.value = option.value
    element.textContent = option.label
    select.append(element)
  }
  select.value = preference.field
  label.append(select)

  const direction = document.createElement('button')
  direction.type = 'button'
  direction.className = 'ghost-button report-sort-direction'

  select.addEventListener('change', () => {
    onChange(normalizeReportSortPreference({
      field: select.value,
      direction: direction.dataset.direction
    }))
  })
  direction.addEventListener('click', () => {
    const nextDirection = direction.dataset.direction === 'asc' ? 'desc' : 'asc'
    onChange(normalizeReportSortPreference({ field: select.value, direction: nextDirection }))
  })

  controls.append(label, direction)
  const filterControls = filterPanel.querySelector('.report-filter-controls')
  filterPanel.insertBefore(controls, filterControls)
  return controls
}

function updateSortControls(controls: HTMLElement, preference: ReportSortPreference) {
  const select = controls.querySelector<HTMLSelectElement>('select[aria-label="並び替え項目"]')
  const direction = controls.querySelector<HTMLButtonElement>('.report-sort-direction')
  if (select && select.value !== preference.field) {
    select.value = preference.field
  }
  if (direction) {
    direction.dataset.direction = preference.direction
    const label = preference.direction === 'asc' ? '昇順 ↑' : '降順 ↓'
    if (direction.textContent !== label) {
      direction.textContent = label
    }
    direction.setAttribute(
      'aria-label',
      preference.direction === 'asc' ? '昇順。クリックで降順' : '降順。クリックで昇順'
    )
  }
}

function matchItemsToReports(items: HTMLElement[], reports: SortableReport[]) {
  const buckets = new Map<string, SortableReport[]>()
  for (const report of reports) {
    const key = reportItemKeyFromReport(report)
    const bucket = buckets.get(key) ?? []
    bucket.push(report)
    buckets.set(key, bucket)
  }

  return items.map((item) => buckets.get(reportItemKeyFromElement(item))?.shift())
}

function reportItemKeyFromReport(report: SortableReport) {
  return [
    report.title,
    report.program || '未分類',
    statusLabels[report.status] || report.status,
    report.asset || '対象未設定',
    report.cvssVersion,
    report.cvssScore || '未設定',
    String(report.pocFiles.length)
  ].join('\u0000')
}

function reportItemKeyFromElement(item: HTMLElement) {
  const title = item.querySelector<HTMLElement>('.item-topline strong')?.textContent?.trim() ?? ''
  const meta = Array.from(item.querySelectorAll<HTMLElement>('.item-meta'))
  const first = splitMeta(meta[0]?.textContent ?? '')
  const second = splitMeta(meta[1]?.textContent ?? '')
  const scoreText = item.querySelector<HTMLElement>('.severity')?.textContent?.trim() ?? ''
  const score = scoreText === 'CVSS未設定' ? '未設定' : scoreText.split(/\s+/).at(-1) ?? '未設定'
  const version = second[1]?.replace(/^CVSS\s+/, '').trim() ?? ''
  const pocCount = second[2]?.match(/PoC\s+(\d+)件/)?.[1] ?? '0'

  return [title, first[0] ?? '', first[1] ?? '', second[0] ?? '', version, score, pocCount].join('\u0000')
}

function splitMeta(value: string) {
  return value.split('·').map((part) => part.trim())
}

function normalizeReport(source: unknown): SortableReport {
  const report = source as Record<string, unknown>
  return {
    id: String(report.id ?? ''),
    title: String(report.title ?? ''),
    program: String(report.program ?? ''),
    asset: String(report.asset ?? ''),
    status: String(report.status ?? 'Draft'),
    cvssVersion: String(report.cvssVersion ?? '3.1'),
    cvssScore: String(report.cvssScore ?? ''),
    cvssVector: String(report.cvssVector ?? ''),
    submittedAt: String(report.submittedAt ?? ''),
    nextActionAt: String(report.nextActionAt ?? ''),
    createdAt: String(report.createdAt ?? ''),
    updatedAt: String(report.updatedAt ?? ''),
    pocFiles: Array.isArray(report.pocFiles) ? report.pocFiles : [],
    rewardStatus: String(report.rewardStatus ?? 'Unknown'),
    rewardAmount: String(report.rewardAmount ?? ''),
    rewardCurrency: String(report.rewardCurrency ?? ''),
    rewardPaidAt: String(report.rewardPaidAt ?? ''),
    rewardNote: String(report.rewardNote ?? ''),
    memo: String(report.memo ?? ''),
    reportUrl: String(report.reportUrl ?? ''),
    maintainerLog: String(report.maintainerLog ?? ''),
    conversationLogs: Array.isArray(report.conversationLogs) ? report.conversationLogs : [],
    tags: Array.isArray(report.tags) ? report.tags.map(String) : []
  }
}

function rewardSearchText(report: SortableReport) {
  return [
    rewardStatusLabels[report.rewardStatus] || report.rewardStatus,
    report.rewardAmount,
    report.rewardCurrency,
    report.rewardPaidAt,
    report.rewardNote
  ].join(' ')
}

function conversationLogsToText(logs: unknown[]) {
  return logs
    .map((entry) => {
      const log = entry as Record<string, unknown>
      return `${String(log.from ?? '')} ${String(log.to ?? '')} ${String(log.communicatedAt ?? '')} ${String(log.body ?? '')}`
    })
    .join(' ')
}
