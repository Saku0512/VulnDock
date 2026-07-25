import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_HIDDEN_STATUS_LABELS,
  shouldHideReportStatus,
  statusLabelFromMeta
} from '../.test-dist/reportVisibility.js'

describe('statusLabelFromMeta', () => {
  it('extracts the status from report metadata', () => {
    assert.equal(statusLabelFromMeta('HackerOne · 公開済み'), '公開済み')
    assert.equal(statusLabelFromMeta('未分類 · 確認中'), '確認中')
  })
})

describe('shouldHideReportStatus', () => {
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
