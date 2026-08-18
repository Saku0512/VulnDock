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

const collator = new Intl.Collator('ja', { numeric: true, sensitivity: 'base' })

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
    return Date.UTC(Number(dateOnly[1]), Number(dateOnly[2]) - 1, Number(dateOnly[3]))
  }
  return new Date(value).getTime()
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
