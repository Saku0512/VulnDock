export const DEFAULT_HIDDEN_STATUS_LABELS = [
  '公開済み',
  '重複',
  '却下',
  '支払済み'
] as const

const defaultStatusOptionLabel = '公開済み等を除外（既定）'
const allStatusOptionLabel = 'すべての状態'
const toggleAttribute = 'data-terminal-status-toggle'
const emptyStateAttribute = 'data-terminal-status-empty'

export function statusLabelFromMeta(meta: string) {
  const segments = meta.split('·')
  return segments[segments.length - 1]?.trim() ?? ''
}

export function shouldHideReportStatus(
  statusLabel: string,
  statusFilter: string,
  includeTerminalStatuses = false
) {
  return statusFilter === 'All'
    && !includeTerminalStatuses
    && DEFAULT_HIDDEN_STATUS_LABELS.some((hiddenStatus) => hiddenStatus === statusLabel)
}

export function setupDefaultReportVisibility(target: HTMLElement) {
  let includeTerminalStatuses = false
  let initialSelectionAdjusted = false

  const applyVisibility = () => {
    const statusSelect = target.querySelector<HTMLSelectElement>('select[aria-label="ステータス"]')
    const filterPanel = statusSelect?.closest<HTMLElement>('.filter-panel')
    const reportList = target.querySelector<HTMLElement>('.report-list')
    if (!statusSelect || !filterPanel || !reportList) {
      return
    }

    const defaultOption = Array.from(statusSelect.options).find((option) => option.value === 'All')
    const optionLabel = includeTerminalStatuses ? allStatusOptionLabel : defaultStatusOptionLabel
    if (defaultOption && defaultOption.textContent !== optionLabel) {
      defaultOption.textContent = optionLabel
    }

    const toggle = ensureTerminalStatusToggle(filterPanel)
    const toggleLabel = includeTerminalStatuses ? '公開済み等を隠す' : '公開済み等も表示'
    toggle.hidden = statusSelect.value !== 'All'
    if (toggle.textContent !== toggleLabel) {
      toggle.textContent = toggleLabel
    }

    const items = Array.from(reportList.querySelectorAll<HTMLElement>('.report-item'))
    for (const item of items) {
      const meta = item.querySelector<HTMLElement>('.item-meta')?.textContent ?? ''
      item.hidden = shouldHideReportStatus(
        statusLabelFromMeta(meta),
        statusSelect.value,
        includeTerminalStatuses
      )
    }

    const visibleItems = items.filter((item) => !item.hidden)
    updateHiddenEmptyState(reportList, items.length > 0 && visibleItems.length === 0 && statusSelect.value === 'All')

    if (!initialSelectionAdjusted && items.length > 0) {
      initialSelectionAdjusted = true
      const activeItem = items.find((item) => item.classList.contains('active'))
      if (activeItem?.hidden && visibleItems[0]) {
        visibleItems[0].click()
      }
    }
  }

  const ensureTerminalStatusToggle = (filterPanel: HTMLElement) => {
    let toggle = filterPanel.querySelector<HTMLButtonElement>(`button[${toggleAttribute}]`)
    if (toggle) {
      return toggle
    }

    toggle = document.createElement('button')
    toggle.type = 'button'
    toggle.className = 'ghost-button'
    toggle.setAttribute(toggleAttribute, '')
    toggle.addEventListener('click', () => {
      includeTerminalStatuses = !includeTerminalStatuses
      applyVisibility()
    })
    filterPanel.append(toggle)
    return toggle
  }

  const observer = new MutationObserver(applyVisibility)
  observer.observe(target, { childList: true, subtree: true, characterData: true })

  const handleChange = () => applyVisibility()
  target.addEventListener('change', handleChange)
  queueMicrotask(applyVisibility)

  return () => {
    observer.disconnect()
    target.removeEventListener('change', handleChange)
  }
}

function updateHiddenEmptyState(reportList: HTMLElement, show: boolean) {
  const current = reportList.querySelector<HTMLElement>(`[${emptyStateAttribute}]`)
  if (!show) {
    current?.remove()
    return
  }
  if (current) {
    return
  }

  const message = document.createElement('p')
  message.className = 'empty-state'
  message.setAttribute(emptyStateAttribute, '')
  message.textContent = '公開済み等の報告を除外しています。上のボタンから表示できます。'
  reportList.append(message)
}
