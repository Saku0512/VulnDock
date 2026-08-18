import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_REPORT_SORT,
  normalizeReportSortPreference,
  reportMatchesSearch,
  sortReports
} from '../.test-dist/reportSortCore.js'

function sortable(id, overrides = {}) {
  return {
    id,
    updatedAt: '',
    createdAt: '',
    submittedAt: '',
    nextActionAt: '',
    cvssScore: '',
    title: '',
    program: '',
    ...overrides
  }
}

function searchable(overrides = {}) {
  return {
    id: 'report-1',
    title: '認証回避',
    program: 'Bugcrowd',
    asset: 'api.example.com',
    status: 'Submitted',
    cvssVersion: '4.0',
    cvssScore: '8.7',
    cvssVector: 'CVSS:4.0/AV:N/AC:L',
    submittedAt: '2026-07-20',
    nextActionAt: '2026-07-30',
    createdAt: '2026-07-19T12:00:00Z',
    updatedAt: '2026-07-21T12:00:00Z',
    pocFiles: [{ name: 'exploit.txt' }],
    rewardStatus: 'Pending',
    rewardAmount: '500',
    rewardCurrency: 'USD',
    rewardPaidAt: '',
    rewardNote: '確認待ち',
    memo: '再現はHTTP/2のみ',
    reportUrl: 'https://example.com/report/1',
    maintainerLog: '',
    conversationLogs: [{ from: '自分', to: 'メンテナー', communicatedAt: '2026-07-21', body: '追加情報' }],
    tags: ['auth', 'api'],
    ...overrides
  }
}

describe('normalizeReportSortPreference', () => {
  it('keeps supported fields and directions', () => {
    assert.deepEqual(
      normalizeReportSortPreference({ field: 'cvssScore', direction: 'asc' }),
      { field: 'cvssScore', direction: 'asc' }
    )
  })

  it('falls back safely for missing or obsolete values', () => {
    assert.deepEqual(
      normalizeReportSortPreference({ field: 'removed-field', direction: 'sideways' }),
      DEFAULT_REPORT_SORT
    )
    assert.deepEqual(normalizeReportSortPreference(null), DEFAULT_REPORT_SORT)
  })
})

describe('sortReports', () => {
  it('sorts dates in either direction', () => {
    const reports = [
      sortable('old', { updatedAt: '2026-07-01T09:00:00Z' }),
      sortable('new', { updatedAt: '2026-07-20T09:00:00Z' }),
      sortable('middle', { updatedAt: '2026-07-10T09:00:00Z' })
    ]

    assert.deepEqual(
      sortReports(reports, { field: 'updatedAt', direction: 'asc' }).map((report) => report.id),
      ['old', 'middle', 'new']
    )
    assert.deepEqual(
      sortReports(reports, { field: 'updatedAt', direction: 'desc' }).map((report) => report.id),
      ['new', 'middle', 'old']
    )
  })

  it('compares CVSS scores numerically', () => {
    const reports = [
      sortable('nine-eight', { cvssScore: '9.8' }),
      sortable('ten', { cvssScore: '10.0' }),
      sortable('four', { cvssScore: '4.0' })
    ]

    assert.deepEqual(
      sortReports(reports, { field: 'cvssScore', direction: 'desc' }).map((report) => report.id),
      ['ten', 'nine-eight', 'four']
    )
  })

  it('keeps missing dates and scores at the end in both directions', () => {
    const dates = [
      sortable('missing', { nextActionAt: '' }),
      sortable('later', { nextActionAt: '2026-08-01' }),
      sortable('sooner', { nextActionAt: '2026-07-28' })
    ]
    const scores = [
      sortable('missing', { cvssScore: '' }),
      sortable('high', { cvssScore: '8.0' }),
      sortable('low', { cvssScore: '3.0' })
    ]

    const datesAscending = sortReports(dates, { field: 'nextActionAt', direction: 'asc' })
    const datesDescending = sortReports(dates, { field: 'nextActionAt', direction: 'desc' })
    const scoresAscending = sortReports(scores, { field: 'cvssScore', direction: 'asc' })
    const scoresDescending = sortReports(scores, { field: 'cvssScore', direction: 'desc' })

    assert.equal(datesAscending[datesAscending.length - 1].id, 'missing')
    assert.equal(datesDescending[datesDescending.length - 1].id, 'missing')
    assert.equal(scoresAscending[scoresAscending.length - 1].id, 'missing')
    assert.equal(scoresDescending[scoresDescending.length - 1].id, 'missing')
  })

  it('uses numeric-aware text ordering', () => {
    const reports = [
      sortable('ten', { title: 'Report 10' }),
      sortable('two', { title: 'Report 2' }),
      sortable('one', { title: 'Report 1' })
    ]

    assert.deepEqual(
      sortReports(reports, { field: 'title', direction: 'asc' }).map((report) => report.id),
      ['one', 'two', 'ten']
    )
  })

  it('preserves input order when values are equal', () => {
    const reports = [
      sortable('first', { program: 'HackerOne' }),
      sortable('second', { program: 'HackerOne' }),
      sortable('third', { program: 'HackerOne' })
    ]

    assert.deepEqual(
      sortReports(reports, { field: 'program', direction: 'desc' }).map((report) => report.id),
      ['first', 'second', 'third']
    )
  })
})

describe('reportMatchesSearch', () => {
  it('matches fields that are not displayed in the list item', () => {
    const report = searchable()

    assert.equal(reportMatchesSearch(report, 'http/2'), true)
    assert.equal(reportMatchesSearch(report, 'exploit.txt'), true)
    assert.equal(reportMatchesSearch(report, '追加情報'), true)
    assert.equal(reportMatchesSearch(report, '見つからない語'), false)
  })
})
