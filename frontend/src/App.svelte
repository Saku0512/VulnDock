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
    nextActionAt: string
    rewardStatus: RewardStatus
    rewardAmount: string
    rewardCurrency: string
    rewardPaidAt: string
    rewardNote: string
    reportUrl: string
    maintainerLog: string
    conversationLogs: ConversationEntry[]
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
  type Participant = '自分' | 'メンテナー'
  type ConversationEntry = {
    id: string
    from: Participant
    to: Participant
    communicatedAt: string
    body: string
  }
  type ConversationDraft = Omit<ConversationEntry, 'id'>
  type CvssVersion = '3.1' | '4.0'
  type CvssRating = 'Critical' | 'High' | 'Medium' | 'Low' | 'None'
  type NextActionFilter = 'All' | 'Overdue' | 'Today' | 'Upcoming'
  type NextActionState = 'none' | 'done' | 'overdue' | 'today' | 'upcoming' | 'later'
  type RewardStatus = 'Unknown' | 'Pending' | 'Paid' | 'None'
  type Status = 'Draft' | 'Submitted' | 'Triaged' | 'Resolved' | 'Duplicate' | 'Rejected' | 'Paid'

  const participants: Participant[] = ['自分', 'メンテナー']
  const cvssVersions: CvssVersion[] = ['3.1', '4.0']
  const cvssRatings: CvssRating[] = ['Critical', 'High', 'Medium', 'Low', 'None']
  const statuses: Status[] = ['Draft', 'Submitted', 'Triaged', 'Resolved', 'Duplicate', 'Rejected', 'Paid']
  const nextActionFilters: NextActionFilter[] = ['Overdue', 'Today', 'Upcoming']
  const rewardStatuses: RewardStatus[] = ['Unknown', 'Pending', 'Paid', 'None']

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

  const nextActionFilterLabels: Record<NextActionFilter, string> = {
    All: 'すべての次アクション',
    Overdue: '期限切れ',
    Today: '今日',
    Upcoming: '7日以内'
  }

  const rewardStatusLabels: Record<RewardStatus, string> = {
    Unknown: '未設定',
    Pending: '未払い',
    Paid: '支払済み',
    None: '報酬なし'
  }

  let reports = $state<Report[]>([])
  let selectedId = $state('')
  let search = $state('')
  let statusFilter = $state<'All' | Status>('All')
  let cvssRatingFilter = $state<'All' | CvssRating>('All')
  let nextActionFilter = $state<'All' | NextActionFilter>('All')
  let draft = $state<ReportDraft>(emptyDraft())
  let conversationDraft = $state<ConversationDraft>(emptyConversationDraft())
  let tagsText = $state('')
  let storePath = $state('')
  let loading = $state(true)
  let saving = $state(false)
  let errorMessage = $state('')
  let pocInput = $state<HTMLInputElement>()
  let hideConversationUntilReopen = $state(false)

  let filteredReports = $derived(reports.filter(matchesFilters))
  let selectedReport = $derived(reports.find((report) => report.id === selectedId))
  let showConversationPanel = $derived(Boolean(selectedReport) && !hideConversationUntilReopen)
  let metrics = $derived(buildMetrics(reports))
  let hasUnsavedChanges = $derived(currentDraftSnapshot() !== savedDraftSnapshot())

  $effect(() => {
    syncCvssFromVector(draft.cvssVector)
  })

  onMount(() => {
    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      if (!hasUnsavedChanges) {
        return
      }

      event.preventDefault()
      event.returnValue = ''
    }

    window.addEventListener('beforeunload', handleBeforeUnload)
    void loadReports()

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload)
    }
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
      nextActionAt: '',
      rewardStatus: 'Unknown',
      rewardAmount: '',
      rewardCurrency: '',
      rewardPaidAt: '',
      rewardNote: '',
      reportUrl: '',
      maintainerLog: '',
      conversationLogs: [],
      tags: [],
      pocFiles: []
    }
  }

  function emptyConversationDraft(): ConversationDraft {
    return {
      from: '自分',
      to: 'メンテナー',
      communicatedAt: localDateTimeNow(),
      body: ''
    }
  }

  async function loadReports() {
    loading = true
    errorMessage = ''

    try {
      reports = (await ListReports()).map(normalizeReport)
      storePath = await StorePath()
      if (reports.length > 0) {
        selectReport(reports[0], { force: true, skipUnsavedCheck: true })
      } else {
        createReport({ skipUnsavedCheck: true })
      }
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : String(error)
    } finally {
      loading = false
    }
  }

  function createReport(options: { skipUnsavedCheck?: boolean } = {}) {
    if (!options.skipUnsavedCheck && !confirmDiscardUnsavedChanges('新規作成')) {
      return
    }

    selectedId = ''
    draft = emptyDraft()
    conversationDraft = emptyConversationDraft()
    hideConversationUntilReopen = false
    tagsText = ''
  }

  function selectReport(report: Report, options: { force?: boolean; showConversation?: boolean; skipUnsavedCheck?: boolean } = {}) {
    if (!options.force && report.id === selectedId) {
      return
    }
    if (!options.skipUnsavedCheck && !confirmDiscardUnsavedChanges('別の報告へ移動')) {
      return
    }

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
      nextActionAt: report.nextActionAt,
      rewardStatus: report.rewardStatus,
      rewardAmount: report.rewardAmount,
      rewardCurrency: report.rewardCurrency,
      rewardPaidAt: report.rewardPaidAt,
      rewardNote: report.rewardNote,
      reportUrl: report.reportUrl,
      maintainerLog: report.maintainerLog,
      conversationLogs: report.conversationLogs.map((log) => ({ ...log })),
      tags: report.tags,
      pocFiles: report.pocFiles
    }
    conversationDraft = emptyConversationDraft()
    hideConversationUntilReopen = options.showConversation === false
    tagsText = report.tags.join(', ')
  }

  async function saveCurrentReport() {
    saving = true
    errorMessage = ''

    try {
      const hideConversationAfterSave = !draft.id || hideConversationUntilReopen
      const preparedDraft = draftForSave()
      const saved = normalizeReport(await SaveReport(new main.ReportDraft({
        ...preparedDraft
      })))
      const index = reports.findIndex((report) => report.id === saved.id)
      if (index >= 0) {
        reports = reports.map((report) => report.id === saved.id ? saved : report)
      } else {
        reports = [saved, ...reports]
      }
      selectReport(saved, { force: true, showConversation: !hideConversationAfterSave, skipUnsavedCheck: true })
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : String(error)
    } finally {
      saving = false
    }
  }

  async function deleteCurrentReport() {
    if (!selectedId) {
      return
    }
    if (!confirmDiscardUnsavedChanges('削除')) {
      return
    }
    if (!confirm('この報告を削除しますか？')) {
      return
    }

    try {
      await DeleteReport(selectedId)
      reports = reports.filter((report) => report.id !== selectedId)
      if (reports.length > 0) {
        selectReport(reports[0], { force: true, skipUnsavedCheck: true })
      } else {
        createReport({ skipUnsavedCheck: true })
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
      report.nextActionAt,
      rewardSearchText(report),
      report.reportUrl,
      report.maintainerLog,
      conversationLogsToText(report.conversationLogs),
      report.pocFiles.map((file) => file.name).join(' '),
      report.tags.join(' ')
    ].join(' ').toLowerCase()

    return (!query || searchable.includes(query))
      && (statusFilter === 'All' || report.status === statusFilter)
      && (cvssRatingFilter === 'All' || cvssRating(report.cvssScore) === cvssRatingFilter)
      && matchesNextActionFilter(report)
  }

  function matchesNextActionFilter(report: Report) {
    if (nextActionFilter === 'All') {
      return true
    }

    const state = nextActionState(report)
    if (nextActionFilter === 'Overdue') {
      return state === 'overdue'
    }
    if (nextActionFilter === 'Today') {
      return state === 'today'
    }
    return state === 'today' || state === 'upcoming'
  }

  function confirmDiscardUnsavedChanges(action: string) {
    if (!hasUnsavedChanges) {
      return true
    }

    return confirm(`${action}すると未保存の変更が破棄されます。続行しますか？`)
  }

  function draftForSave(): ReportDraft {
    return {
      ...draft,
      conversationLogs: conversationLogsForSave(),
      tags: tagsFromText(tagsText)
    }
  }

  function conversationLogsForSave() {
    const logs = draft.conversationLogs.map((log) => ({ ...log }))
    const pendingLog = pendingConversationLog()
    return pendingLog ? [...logs, pendingLog] : logs
  }

  function pendingConversationLog(): ConversationEntry | null {
    const body = conversationDraft.body.trim()
    if (!body) {
      return null
    }

    const from = normalizeParticipant(conversationDraft.from, '自分')
    const to = normalizeRecipient(conversationDraft.to, from)
    return {
      id: newConversationEntryId(),
      from,
      to,
      communicatedAt: conversationDraft.communicatedAt,
      body
    }
  }

  function currentDraftSnapshot() {
    return reportSnapshot(draftForComparison())
  }

  function savedDraftSnapshot() {
    return reportSnapshot(selectedReport ?? emptyDraft())
  }

  function draftForComparison(): ReportDraft {
    const pendingLog = pendingConversationLogForComparison()
    return {
      ...draft,
      conversationLogs: pendingLog
        ? [...draft.conversationLogs, pendingLog]
        : draft.conversationLogs,
      tags: tagsFromText(tagsText)
    }
  }

  function pendingConversationLogForComparison(): ConversationEntry | null {
    const body = conversationDraft.body.trim()
    if (!body) {
      return null
    }

    const from = normalizeParticipant(conversationDraft.from, '自分')
    return {
      id: 'pending',
      from,
      to: normalizeRecipient(conversationDraft.to, from),
      communicatedAt: conversationDraft.communicatedAt.trim(),
      body
    }
  }

  function reportSnapshot(source: Report | ReportDraft) {
    return JSON.stringify({
      id: source.id,
      title: withDefault(source.title.trim(), 'Untitled report'),
      program: source.program.trim(),
      asset: source.asset.trim(),
      cvssVersion: normalizeCvssVersion(source.cvssVersion),
      cvssScore: normalizeCvssScore(source.cvssScore),
      cvssVector: source.cvssVector.trim(),
      status: normalizeStatus(source.status),
      submittedAt: source.submittedAt.trim(),
      nextActionAt: source.nextActionAt.trim(),
      rewardStatus: normalizeRewardStatus(source.rewardStatus),
      rewardAmount: source.rewardAmount.trim(),
      rewardCurrency: source.rewardCurrency.trim().toUpperCase(),
      rewardPaidAt: source.rewardPaidAt.trim(),
      rewardNote: source.rewardNote.trim(),
      reportUrl: source.reportUrl.trim(),
      maintainerLog: '',
      conversationLogs: source.conversationLogs
        .map((log) => ({
          id: log.id,
          from: normalizeParticipant(log.from, '自分'),
          to: normalizeRecipient(log.to, normalizeParticipant(log.from, '自分')),
          communicatedAt: log.communicatedAt.trim(),
          body: log.body.trim()
        }))
        .filter((log) => log.body),
      tags: normalizeTags(source.tags),
      pocFiles: source.pocFiles.map((file) => ({
        name: file.name.trim(),
        type: file.type.trim(),
        size: Math.max(0, Number(file.size) || 0),
        data: file.data.trim()
      }))
    })
  }

  function normalizeReport(source: unknown): Report {
    const report = source as Record<string, unknown>
    const maintainerLog = String(report.maintainerLog ?? '')
    const conversationLogs = normalizeConversationLogs(report.conversationLogs, maintainerLog)

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
      nextActionAt: String(report.nextActionAt ?? ''),
      rewardStatus: normalizeRewardStatus(String(report.rewardStatus ?? 'Unknown')),
      rewardAmount: String(report.rewardAmount ?? ''),
      rewardCurrency: String(report.rewardCurrency ?? ''),
      rewardPaidAt: String(report.rewardPaidAt ?? ''),
      rewardNote: String(report.rewardNote ?? ''),
      reportUrl: String(report.reportUrl ?? ''),
      maintainerLog: '',
      conversationLogs,
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

  function normalizeRewardStatus(value: string): RewardStatus {
    return rewardStatuses.includes(value as RewardStatus) ? value as RewardStatus : 'Unknown'
  }

  function tagsFromText(value: string) {
    return normalizeTags(value.split(','))
  }

  function normalizeTags(tags: string[]) {
    const seen = new Set<string>()
    const next: string[] = []
    for (const tagValue of tags) {
      const tag = tagValue.trim().replace(/^#+|#+$/g, '')
      if (!tag) {
        continue
      }

      const key = tag.toLowerCase()
      if (seen.has(key)) {
        continue
      }
      seen.add(key)
      next.push(tag)
    }
    return next
  }

  function withDefault(value: string, fallback: string) {
    return value || fallback
  }

  function normalizeConversationLogs(source: unknown, legacyLog = ''): ConversationEntry[] {
    const logs = Array.isArray(source)
      ? source
          .map((entry) => entry as Record<string, unknown>)
          .map((entry, index) => {
            const from = normalizeParticipant(String(entry.from ?? ''), '自分')
            const to = normalizeRecipient(String(entry.to ?? ''), from)
            return {
              id: String(entry.id ?? `conversation_legacy_${index}`),
              from,
              to,
              communicatedAt: String(entry.communicatedAt ?? ''),
              body: String(entry.body ?? '').trim()
            }
          })
          .filter((entry) => entry.body)
      : []

    legacyLog = legacyLog.trim()
    if (logs.length === 0 && legacyLog) {
      return [{
        id: 'conversation_legacy_text',
        from: '自分',
        to: 'メンテナー',
        communicatedAt: '',
        body: legacyLog
      }]
    }

    return logs
  }

  function normalizeParticipant(value: string, fallback: Participant): Participant {
    return participants.includes(value as Participant) ? value as Participant : fallback
  }

  function normalizeRecipient(value: string, from: Participant): Participant {
    const recipient = normalizeParticipant(value, from === '自分' ? 'メンテナー' : '自分')
    return recipient === from ? (from === '自分' ? 'メンテナー' : '自分') : recipient
  }

  function buildMetrics(source: Report[]) {
    const open = source.filter((report) => !['Resolved', 'Rejected', 'Duplicate', 'Paid'].includes(report.status)).length
    const triaged = source.filter((report) => report.status === 'Triaged').length
    const due = source.filter((report) => ['overdue', 'today'].includes(nextActionState(report))).length
    const attachments = source.reduce((sum, report) => sum + report.pocFiles.length, 0)
    return { open, triaged, due, attachments }
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

  function nextActionLabel(report: Report) {
    const date = parseLocalDate(report.nextActionAt)
    if (!date) {
      return ''
    }

    const dateLabel = report.nextActionAt.replace('T', ' ')
    if (isCompletedStatus(report.status)) {
      return `次アクション ${dateLabel}`
    }

    const delta = dayDelta(date)
    if (delta < 0) {
      return `期限切れ ${Math.abs(delta)}日`
    }
    if (delta === 0) {
      return '次アクション 今日'
    }
    if (delta <= 7) {
      return `次アクション あと${delta}日`
    }
    return `次アクション ${dateLabel}`
  }

  function nextActionClass(report: Report) {
    return `next-action-${nextActionState(report)}`
  }

  function rewardLabel(report: Report) {
    if (!hasRewardInfo(report)) {
      return ''
    }

    const amount = rewardAmountLabel(report)
    if (report.rewardStatus === 'None') {
      return '報酬なし'
    }
    if (amount) {
      return `報酬 ${amount}`
    }
    return `報酬 ${rewardStatusLabels[report.rewardStatus]}`
  }

  function rewardAmountLabel(report: Report) {
    const amount = report.rewardAmount.trim()
    if (!amount) {
      return ''
    }

    const currency = report.rewardCurrency.trim().toUpperCase()
    return currency ? `${amount} ${currency}` : amount
  }

  function rewardClass(report: Report) {
    return `reward-${report.rewardStatus.toLowerCase()}`
  }

  function rewardSearchText(report: Report) {
    return [
      rewardStatusLabels[report.rewardStatus],
      report.rewardAmount,
      report.rewardCurrency,
      report.rewardPaidAt,
      report.rewardNote
    ].join(' ')
  }

  function hasRewardInfo(report: Report) {
    return report.rewardStatus !== 'Unknown'
      || Boolean(report.rewardAmount.trim())
      || Boolean(report.rewardCurrency.trim())
      || Boolean(report.rewardPaidAt.trim())
      || Boolean(report.rewardNote.trim())
  }

  function nextActionState(report: Report): NextActionState {
    const date = parseLocalDate(report.nextActionAt)
    if (!date) {
      return 'none'
    }
    if (isCompletedStatus(report.status)) {
      return 'done'
    }

    const delta = dayDelta(date)
    if (delta < 0) {
      return 'overdue'
    }
    if (delta === 0) {
      return 'today'
    }
    if (delta <= 7) {
      return 'upcoming'
    }
    return 'later'
  }

  function isCompletedStatus(status: Status) {
    return ['Resolved', 'Rejected', 'Duplicate', 'Paid'].includes(status)
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

  function addConversationLog() {
    const body = conversationDraft.body.trim()
    if (!body) {
      return
    }

    const from = normalizeParticipant(conversationDraft.from, '自分')
    const to = normalizeRecipient(conversationDraft.to, from)
    draft.conversationLogs = [
      ...draft.conversationLogs,
      {
        id: newConversationEntryId(),
        from,
        to,
        communicatedAt: conversationDraft.communicatedAt,
        body
      }
    ]
    conversationDraft = {
      from,
      to,
      communicatedAt: localDateTimeNow(),
      body: ''
    }
  }

  function removeConversationLog(id: string) {
    draft.conversationLogs = draft.conversationLogs.filter((log) => log.id !== id)
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

  function formatConversationTime(value: string) {
    if (!value.trim()) {
      return '日時未設定'
    }
    return value.replace('T', ' ')
  }

  function contactElapsedLabel(report: Report) {
    const latest = latestConversationTime(report.conversationLogs)
    if (!latest) {
      if (report.conversationLogs.length > 0) {
        return '連絡日時未設定'
      }

      const reportDate = reportBaseDate(report)
      if (!reportDate) {
        return '連絡なし：報告日未設定'
      }
      return `連絡なし：報告から${daysSince(reportDate)}日経過`
    }

    const elapsedDays = daysSince(latest)
    if (elapsedDays <= 0) {
      return '最終連絡 今日'
    }
    return `最終連絡から${elapsedDays}日経過`
  }

  function contactElapsedClass(report: Report) {
    const latest = latestConversationTime(report.conversationLogs)
    if (!latest) {
      if (report.conversationLogs.length > 0) {
        return 'contact-age-undated'
      }

      const reportDate = reportBaseDate(report)
      if (!reportDate) {
        return 'contact-age-none'
      }

      const elapsedDays = daysSince(reportDate)
      if (elapsedDays >= 14) {
        return 'contact-age-stale'
      }
      if (elapsedDays >= 7) {
        return 'contact-age-watch'
      }
      return 'contact-age-none'
    }

    const elapsedDays = daysSince(latest)
    if (elapsedDays >= 14) {
      return 'contact-age-stale'
    }
    if (elapsedDays >= 7) {
      return 'contact-age-watch'
    }
    return 'contact-age-fresh'
  }

  function latestConversationTime(logs: ConversationEntry[]) {
    let latest = 0
    for (const log of logs) {
      const time = new Date(log.communicatedAt).getTime()
      if (Number.isFinite(time) && time > latest) {
        latest = time
      }
    }
    return latest > 0 ? new Date(latest) : null
  }

  function reportBaseDate(report: Report) {
    return parseLocalDate(report.submittedAt) || parseLocalDate(report.createdAt)
  }

  function parseLocalDate(value: string) {
    value = value.trim()
    if (!value) {
      return null
    }

    const dateOnly = value.match(/^(\d{4})-(\d{2})-(\d{2})$/)
    if (dateOnly) {
      return new Date(Number(dateOnly[1]), Number(dateOnly[2]) - 1, Number(dateOnly[3]))
    }

    const date = new Date(value)
    return Number.isFinite(date.getTime()) ? date : null
  }

  function daysSince(date: Date) {
    return Math.max(0, -dayDelta(date))
  }

  function dayDelta(date: Date) {
    const today = startOfLocalDay(new Date()).getTime()
    const target = startOfLocalDay(date).getTime()
    return Math.floor((target - today) / 86400000)
  }

  function startOfLocalDay(date: Date) {
    return new Date(date.getFullYear(), date.getMonth(), date.getDate())
  }

  function conversationLogsToText(logs: ConversationEntry[]) {
    return logs
      .map((log) => `${log.from} ${log.to} ${log.communicatedAt} ${log.body}`)
      .join(' ')
  }

  function localDateTimeNow() {
    const now = new Date()
    const local = new Date(now.getTime() - now.getTimezoneOffset() * 60000)
    return local.toISOString().slice(0, 16)
  }

  function newConversationEntryId() {
    return `conversation_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
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
      <button class="icon-button" type="button" title="新規報告" onclick={() => createReport()}>+</button>
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
        <span>{metrics.due}</span>
        <p>要確認</p>
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
      <select bind:value={nextActionFilter} aria-label="次アクション">
        <option value="All">{nextActionFilterLabels.All}</option>
        {#each nextActionFilters as filter}
          <option value={filter}>{nextActionFilterLabels[filter]}</option>
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
            <span class={`contact-age ${contactElapsedClass(report)}`}>{contactElapsedLabel(report)}</span>
            {#if report.nextActionAt}
              <span class={`next-action ${nextActionClass(report)}`}>{nextActionLabel(report)}</span>
            {/if}
            {#if hasRewardInfo(report)}
              <span class={`reward-badge ${rewardClass(report)}`}>{rewardLabel(report)}</span>
            {/if}
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
        <span class:dirty={hasUnsavedChanges} class="save-status">
          {saving ? '保存中...' : hasUnsavedChanges ? '未保存の変更' : '保存済み'}
        </span>
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
      <label>
        次アクション
        <input bind:value={draft.nextActionAt} type="date" />
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
      <section class="reward-panel">
        <div class="poc-header">
          <p class="eyebrow">報酬メモ</p>
        </div>
        <div class="reward-grid">
          <label>
            状態
            <select bind:value={draft.rewardStatus}>
              {#each rewardStatuses as rewardStatus}
                <option value={rewardStatus}>{rewardStatusLabels[rewardStatus]}</option>
              {/each}
            </select>
          </label>
          <label>
            金額
            <input bind:value={draft.rewardAmount} inputmode="decimal" placeholder="500.00" />
          </label>
          <label>
            通貨
            <input bind:value={draft.rewardCurrency} placeholder="USD / JPY" />
          </label>
          <label>
            支払日
            <input bind:value={draft.rewardPaidAt} type="date" />
          </label>
          <label class="reward-note">
            メモ
            <textarea bind:value={draft.rewardNote} rows="2" placeholder="支払い条件や補足"></textarea>
          </label>
        </div>
      </section>

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

      {#if showConversationPanel}
        <section class="conversation-panel">
          <div class="poc-header">
            <p class="eyebrow">メンテナー会話ログ</p>
            <button class="ghost-button attach-button" type="button" onclick={addConversationLog} disabled={!conversationDraft.body.trim()}>
              追加
            </button>
          </div>

          <div class="conversation-form">
            <label>
              送信者
              <select bind:value={conversationDraft.from}>
                {#each participants as participant}
                  <option value={participant}>{participant}</option>
                {/each}
              </select>
            </label>
            <label>
              宛先
              <select bind:value={conversationDraft.to}>
                {#each participants as participant}
                  <option value={participant}>{participant}</option>
                {/each}
              </select>
            </label>
            <label>
              日時
              <input bind:value={conversationDraft.communicatedAt} type="datetime-local" />
            </label>
            <label class="conversation-body">
              内容
              <textarea bind:value={conversationDraft.body} rows="4" placeholder="伝えた内容"></textarea>
            </label>
          </div>

          <div class="conversation-list">
            {#each draft.conversationLogs as log (log.id)}
              <article class="conversation-item">
                <div>
                  <strong>{log.from} → {log.to}</strong>
                  <span>{formatConversationTime(log.communicatedAt)}</span>
                </div>
                <p>{log.body}</p>
                <button class="small-button" type="button" onclick={() => removeConversationLog(log.id)}>削除</button>
              </article>
            {:else}
              <p class="muted">未記録</p>
            {/each}
          </div>
        </section>
      {/if}

      <section class="storage-note">
        <p class="eyebrow">保存先</p>
        <code>{storePath || '未取得'}</code>
      </section>
    </div>
  </section>
</main>
