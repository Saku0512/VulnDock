import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  selectedBackupFile,
  validateBackupPasswordPair,
  validateRestorePassword
} from '../.test-dist/backup.js'

describe('validateBackupPasswordPair', () => {
  it('returns a password when both fields match', () => {
    assert.deepEqual(validateBackupPasswordPair('secret', 'secret'), { ok: true, password: 'secret' })
  })

  it('rejects a blank password', () => {
    assert.deepEqual(validateBackupPasswordPair('  ', '  '), {
      ok: false,
      errorMessage: 'バックアップ用パスワードを入力してください。'
    })
  })

  it('returns an error when the confirmation does not match', () => {
    assert.deepEqual(validateBackupPasswordPair('secret', 'different'), {
      ok: false,
      errorMessage: 'バックアップ用パスワードが一致しません。'
    })
  })
})

describe('validateRestorePassword', () => {
  it('returns a password when entered', () => {
    assert.deepEqual(validateRestorePassword('secret'), { ok: true, password: 'secret' })
  })

  it('rejects a blank password', () => {
    assert.deepEqual(validateRestorePassword('\n\t'), {
      ok: false,
      errorMessage: 'バックアップのパスワードを入力してください。'
    })
  })
})

describe('selectedBackupFile', () => {
  it('returns null when no restore file is selected', () => {
    assert.equal(selectedBackupFile(null), null)
    assert.equal(selectedBackupFile({ length: 0 }), null)
  })

  it('returns the first selected file-like object', () => {
    const file = { name: 'backup.zip' }

    assert.equal(selectedBackupFile({ 0: file, length: 1 }), file)
  })
})
