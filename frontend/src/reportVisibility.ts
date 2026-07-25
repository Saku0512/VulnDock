export const DEFAULT_HIDDEN_STATUS_LABELS = [
  '公開済み',
  '重複',
  '却下',
  '支払済み'
] as const

export type ReportFilterSnapshot = {
  statusLabel: string
  cvssRating: string
  actionState: string
}

export type ReportFilterSelections = {
  statuses: readonly string[]
  cvssRatings: readonly string[]
  actions: readonly string[]
  includeTerminalStatuses?: boolean
}

type FilterCategory = 'status' | 'cvss' | 'action'
type FilterOption = {
  value: string
  label: string
}

type FilterGroup = {
  category: FilterCategory
  label: string
  options: FilterOption[]
}

const controlsAttribute = 'data-report-filter-controls'
const chipAttribute = 'data-report-filter-chip'
const terminalToggleAttribute = 'data-terminal-status-toggle'
const clearAttribute = 'data-report-filter-clear'
const summaryAttribute = 'data-report-filter-summary'
const emptyStateAttribute = 'data-report-filter-empty'
const hiddenAttribute = 'data-report-filter-hidden'

export function statusLabelFromMeta(meta: string) {
  const segments = meta.split('·')
  return segments[segments.length - 1]?.trim() ?? ''
}

export function cvssRatingFromClassNames(classNames: readonly string[]) {
  const className = classNames.find((value) => value.startsWith('severity-'))
  if (!className) {
    return 'None'
  }

  const rating = className.slice('severity-'.length)
  return rating ? `${rating[0].toUpperCase()}${rating.slice(1)}` : 'None'
}

export function actionStateFromClassNames(classNames: readonly string[]) {
  const className = classNames.find((value) => value.startsWith('next-action-'))
  return className?.slice('next-action-'.length) || 'none'
}

export function actionFilterMatches(filter: string, actionState: string) {
  if (filter === 'Overdue') {
    return actionState === 'overdue'
  }
  if (filter === 'Today') {
    return actionState === 'today'
  }
  if (filter === 'Upcoming') {
    return actionState === 'today' || actionState === 'upcoming'
  }
  return false
}

export function reportMatchesFilters(
  report: ReportFilterSnapshot,
  filters: ReportFilterSelections
) {
  if (filters.statuses.length > 0) {
    if (!filters.statuses.includes(report.statusLabel)) {
      return false
    }
  } else if (!filters.includeTerminalStatuses && isTerminalStatus(report.statusLabel)) {
    return false
  }

  if (filters.cvssRatings.length > 0 && !filters.cvssRatings.includes(report.cvssRating)) {
    return false
  }

  if (filters.actions.length > 0
    && !filters.actions.some((filter) => actionFilterMatches(filter, report.actionState))) {
    return false
  }

  return true
}

export function shouldHideReportStatus(
  statusLabel: string,
  statusFilter: string,
  includeTerminalStatuses = false
) {
  return statusFilter === 'All'
    && !includeTerminalStatuses
    && isTerminalStatus(statusLabel)
}

export function setupDefaultReportVisibility(target: HTMLElement) {
  const selections: Record<FilterCategory, Set<string>> = {
    status: new Set(),
    cvss: new Set(),
    action: new Set()
  }
  let includeTerminalStatuses = false
  let initialSelectionAdjusted = false

  const applyVisibility = () => {
    const statusSelect = target.querySelector<HTMLSelectElement>('select[aria-label="ステータス"]')
    const cvssSelect = target.querySelector<HTMLSelectElement>('select[aria-label="CVSS評価"]')
    const actionSelect = target.querySelector<HTMLSelectElement>('select[aria-label="次アクション"]')
    const filterPanel = statusSelect?.closest<HTMLElement>('.filter-panel')
    const reportList = target.querySelector<HTMLElement>('.report-list')
    if (!statusSelect || !cvssSelect || !actionSelect || !filterPanel || !reportList) {
      return
    }

    const selects = [statusSelect, cvssSelect, actionSelect]
    for (const select of selects) {
      resetNativeSelect(select)
      select.hidden = true
    }

    const groups: FilterGroup[] = [
      {
        category: 'status',
        label: '状態',
        options: optionsFromSelect(statusSelect, true)
      },
      {
        category: 'cvss',
        label: 'CVSS',
        options: optionsFromSelect(cvssSelect)
      },
      {
        category: 'action',
        label: 'アクション',
        options: optionsFromSelect(actionSelect)
      }
    ]

    ensureFilterControls(filterPanel, groups, selections, {
      onToggle(category, value) {
        const selected = selections[category]
        if (selected.has(value)) {
          selected.delete(value)
        } else {
          selected.add(value)
        }
        if (category === 'status' && selected.size > 0) {
          includeTerminalStatuses = false
        }
        applyVisibility()
      },
      onToggleTerminalStatuses() {
        includeTerminalStatuses = !includeTerminalStatuses
        applyVisibility()
      },
      onClear() {
        for (const selected of Object.values(selections)) {
          selected.clear()
        }
        includeTerminalStatuses = false
        applyVisibility()
      }
    })

    updateFilterControls(filterPanel, selections, includeTerminalStatuses)

    const filters = currentSelections(selections, includeTerminalStatuses)
    const items = Array.from(reportList.querySelectorAll<HTMLElement>('.report-item'))
    for (const item of items) {
      item.toggleAttribute(hiddenAttribute, !reportMatchesFilters(reportSnapshotFromItem(item), filters))
    }

    const visibleItems = items.filter((item) => !item.hasAttribute(hiddenAttribute))
    updateHiddenEmptyState(
      reportList,
      items.length > 0 && visibleItems.length === 0,
      hasExplicitFilters(selections, includeTerminalStatuses)
    )

    if (!initialSelectionAdjusted && items.length > 0) {
      initialSelectionAdjusted = true
      const activeItem = items.find((item) => item.classList.contains('active'))
      if (activeItem?.hasAttribute(hiddenAttribute) && visibleItems[0]) {
        visibleItems[0].click()
      }
    }
  }

  const observer = new MutationObserver(applyVisibility)
  observer.observe(target, { childList: true, subtree: true, characterData: true })

  queueMicrotask(applyVisibility)

  return () => {
    observer.disconnect()
  }
}

function isTerminalStatus(statusLabel: string) {
  return DEFAULT_HIDDEN_STATUS_LABELS.some((status) => status === statusLabel)
}

function optionsFromSelect(select: HTMLSelectElement, useLabelAsValue = false): FilterOption[] {
  return Array.from(select.options)
    .filter((option) => option.value !== 'All')
    .map((option) => {
      const label = option.textContent?.trim() || option.value
      return {
        value: useLabelAsValue ? label : option.value,
        label
      }
    })
}

function resetNativeSelect(select: HTMLSelectElement) {
  if (select.value === 'All') {
    return
  }
  select.value = 'All'
  select.dispatchEvent(new Event('change', { bubbles: true }))
}

function reportSnapshotFromItem(item: HTMLElement): ReportFilterSnapshot {
  const statusMeta = item.querySelector<HTMLElement>('.item-meta')?.textContent ?? ''
  const severity = item.querySelector<HTMLElement>('.severity')
  const nextAction = item.querySelector<HTMLElement>('.next-action')

  return {
    statusLabel: statusLabelFromMeta(statusMeta),
    cvssRating: cvssRatingFromClassNames(severity ? Array.from(severity.classList) : []),
    actionState: actionStateFromClassNames(nextAction ? Array.from(nextAction.classList) : [])
  }
}

function currentSelections(
  selections: Record<FilterCategory, Set<string>>,
  includeTerminalStatuses: boolean
): ReportFilterSelections {
  return {
    statuses: Array.from(selections.status),
    cvssRatings: Array.from(selections.cvss),
    actions: Array.from(selections.action),
    includeTerminalStatuses
  }
}

function ensureFilterControls(
  filterPanel: HTMLElement,
  groups: FilterGroup[],
  selections: Record<FilterCategory, Set<string>>,
  handlers: {
    onToggle: (category: FilterCategory, value: string) => void
    onToggleTerminalStatuses: () => void
    onClear: () => void
  }
) {
  if (filterPanel.querySelector(`[${controlsAttribute}]`)) {
    return
  }

  const controls = document.createElement('div')
  controls.className = 'report-filter-controls'
  controls.setAttribute(controlsAttribute, '')

  for (const group of groups) {
    const groupElement = document.createElement('div')
    groupElement.className = 'report-filter-group'
    groupElement.setAttribute('role', 'group')
    groupElement.setAttribute('aria-label', `${group.label}フィルター`)

    const label = document.createElement('span')
    label.className = 'report-filter-label'
    label.textContent = group.label
    groupElement.append(label)

    const options = document.createElement('div')
    options.className = 'report-filter-options'
    for (const option of group.options) {
      const button = document.createElement('button')
      button.type = 'button'
      button.className = 'report-filter-chip'
      button.textContent = option.label
      button.setAttribute(chipAttribute, '')
      button.dataset.filterCategory = group.category
      button.dataset.filterValue = option.value
      button.setAttribute('aria-pressed', String(selections[group.category].has(option.value)))
      button.addEventListener('click', () => handlers.onToggle(group.category, option.value))
      options.append(button)
    }
    groupElement.append(options)
    controls.append(groupElement)
  }

  const actionRow = document.createElement('div')
  actionRow.className = 'report-filter-actions'

  const summary = document.createElement('p')
  summary.className = 'report-filter-summary'
  summary.setAttribute(summaryAttribute, '')
  actionRow.append(summary)

  const actionButtons = document.createElement('div')
  actionButtons.className = 'report-filter-action-buttons'

  const terminalToggle = document.createElement('button')
  terminalToggle.type = 'button'
  terminalToggle.className = 'ghost-button'
  terminalToggle.setAttribute(terminalToggleAttribute, '')
  terminalToggle.addEventListener('click', handlers.onToggleTerminalStatuses)
  actionButtons.append(terminalToggle)

  const clear = document.createElement('button')
  clear.type = 'button'
  clear.className = 'ghost-button'
  clear.textContent = 'フィルターをクリア'
  clear.setAttribute(clearAttribute, '')
  clear.addEventListener('click', handlers.onClear)
  actionButtons.append(clear)

  actionRow.append(actionButtons)
  controls.append(actionRow)
  filterPanel.append(controls)
}

function updateFilterControls(
  filterPanel: HTMLElement,
  selections: Record<FilterCategory, Set<string>>,
  includeTerminalStatuses: boolean
) {
  const chips = Array.from(filterPanel.querySelectorAll<HTMLButtonElement>(`button[${chipAttribute}]`))
  for (const chip of chips) {
    const category = chip.dataset.filterCategory as FilterCategory
    const value = chip.dataset.filterValue ?? ''
    chip.setAttribute('aria-pressed', String(selections[category]?.has(value) ?? false))
  }

  const terminalToggle = filterPanel.querySelector<HTMLButtonElement>(`button[${terminalToggleAttribute}]`)
  if (terminalToggle) {
    terminalToggle.hidden = selections.status.size > 0
    const label = includeTerminalStatuses ? '公開済み等を隠す' : '公開済み等も表示'
    if (terminalToggle.textContent !== label) {
      terminalToggle.textContent = label
    }
  }

  const activeCount = Object.values(selections).reduce((sum, selected) => sum + selected.size, 0)
  const summary = filterPanel.querySelector<HTMLElement>(`[${summaryAttribute}]`)
  if (summary) {
    const text = activeCount > 0
      ? `${activeCount}件の条件を選択中`
      : includeTerminalStatuses
        ? 'すべての状態を表示中'
        : '公開済み等を除外中'
    if (summary.textContent !== text) {
      summary.textContent = text
    }
  }

  const clear = filterPanel.querySelector<HTMLButtonElement>(`button[${clearAttribute}]`)
  if (clear) {
    clear.disabled = activeCount === 0 && !includeTerminalStatuses
  }
}

function hasExplicitFilters(
  selections: Record<FilterCategory, Set<string>>,
  includeTerminalStatuses: boolean
) {
  return includeTerminalStatuses || Object.values(selections).some((selected) => selected.size > 0)
}

function updateHiddenEmptyState(reportList: HTMLElement, show: boolean, explicitFilters: boolean) {
  const current = reportList.querySelector<HTMLElement>(`[${emptyStateAttribute}]`)
  if (!show) {
    current?.remove()
    return
  }

  const message = explicitFilters
    ? '選択したフィルターに一致する報告はありません。'
    : '公開済み等の報告を除外しています。フィルターから表示できます。'
  if (current) {
    if (current.textContent !== message) {
      current.textContent = message
    }
    return
  }

  const emptyState = document.createElement('p')
  emptyState.className = 'empty-state'
  emptyState.setAttribute(emptyStateAttribute, '')
  emptyState.textContent = message
  reportList.append(emptyState)
}
