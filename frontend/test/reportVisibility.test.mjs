import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_HIDDEN_STATUS_LABELS,
  actionFilterMatches,
  actionStateFromClassNames,
  cvssRatingFromClassNames,
  reportMatchesFilters,
  shouldHideReportStatus,
  statusLabelFromMeta
} from '../.test-dist/reportVisibility.js'

describe('report metadata parsing', () => {
  it('extracts the status from report metadata', () => {
    assert.equal(statusLabelFromMeta('HackerOne · 公開済み'), '公開済み')
    assert.equal(statusLabelFromMeta('未分類 · 確認中'), '確認中')
  })

  it('extracts CVSS ratings and next-action states from classes', () => {
    assert.equal(cvssRatingFromClassNames(['severity', 'severity-critical']), 'Critical')
    assert.equal(cvssRatingFromClassNames(['severity', 'severity-none']), 'None')
    assert.equal(actionStateFromClassNames(['next-action', 'next-action-overdue']), 'overdue')
    assert.equal(actionStateFromClassNames([]), 'none')
  })
})

describe('default terminal status visibility', () => {
  it('hides the configured terminal statuses in the default view', () => {
    for (const status of DEFAULT_HIDDEN_STATUS_LABELS) {
      assert.equal(shouldHideReportStatus(status, 'All'), true)
    }
  })

  it('keeps other statuses visible in the default view', () => {
    for (const status of ['下書き', '提出済み', '確認中', '修正済み']) {
      assert.equal(shouldHideReportStatus(status, 'All'), false)
    }
  })

  it('shows terminal statuses when explicitly requested', () => {
    assert.equal(shouldHideReportStatus('公開済み', 'Published'), false)
    assert.equal(shouldHideReportStatus('公開済み', 'All', true), false)
  })
})

describe('reportMatchesFilters', () => {
  const draftHighToday = {
    statusLabel: '下書き',
    cvssRating: 'High',
    actionState: 'today'
  }

  it('uses OR logic inside a category', () => {
    const filters = {
      statuses: ['下書き', '提出済み'],
      cvssRatings: [],
      actions: []
    }

    assert.equal(reportMatchesFilters(draftHighToday, filters), true)
    assert.equal(reportMatchesFilters({ ...draftHighToday, statusLabel: '提出済み' }, filters), true)
    assert.equal(reportMatchesFilters({ ...draftHighToday, statusLabel: '確認中' }, filters), false)
  })

  it('uses AND logic across filter categories', () => {
    const filters = {
      statuses: ['下書き'],
      cvssRatings: ['High'],
      actions: ['Today']
    }

    assert.equal(reportMatchesFilters(draftHighToday, filters), true)
    assert.equal(reportMatchesFilters({ ...draftHighToday, cvssRating: 'Medium' }, filters), false)
    assert.equal(reportMatchesFilters({ ...draftHighToday, actionState: 'overdue' }, filters), false)
  })

  it('lets explicit status selections override the default terminal-status exclusion', () => {
    const published = {
      statusLabel: '公開済み',
      cvssRating: 'High',
      actionState: 'done'
    }

    assert.equal(reportMatchesFilters(published, {
      statuses: [],
      cvssRatings: [],
      actions: []
    }), false)
    assert.equal(reportMatchesFilters(published, {
      statuses: ['公開済み'],
      cvssRatings: [],
      actions: []
    }), true)
    assert.equal(reportMatchesFilters(published, {
      statuses: [],
      cvssRatings: [],
      actions: [],
      includeTerminalStatuses: true
    }), true)
  })
})

describe('actionFilterMatches', () => {
  it('treats the upcoming filter as today or within seven days', () => {
    assert.equal(actionFilterMatches('Upcoming', 'today'), true)
    assert.equal(actionFilterMatches('Upcoming', 'upcoming'), true)
    assert.equal(actionFilterMatches('Upcoming', 'later'), false)
  })
})
