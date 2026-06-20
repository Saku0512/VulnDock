import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { calculateCvss, inferCvssVersion } from '../.test-dist/cvss.js'

describe('inferCvssVersion', () => {
  it('detects supported vector prefixes', () => {
    assert.equal(inferCvssVersion('CVSS:3.1/AV:N/AC:L'), '3.1')
    assert.equal(inferCvssVersion('  CVSS:4.0/AV:N/AC:L'), '4.0')
    assert.equal(inferCvssVersion('AV:N/AC:L'), '')
  })
})

describe('calculateCvss', () => {
  it('calculates CVSS 3.1 base scores', () => {
    assert.equal(
      calculateCvss('3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
      '9.8'
    )
    assert.equal(
      calculateCvss('3.1', 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N'),
      '3.9'
    )
    assert.equal(
      calculateCvss('3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
      '0.0'
    )
  })

  it('calculates CVSS 4.0 base scores', () => {
    assert.equal(
      calculateCvss('4.0', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'),
      '10.0'
    )
    assert.equal(
      calculateCvss('4.0', 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N'),
      '1.0'
    )
    assert.equal(
      calculateCvss('4.0', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'),
      '0.0'
    )
  })

  it('returns an empty score for incomplete or invalid vectors', () => {
    assert.equal(calculateCvss('3.1', 'CVSS:3.1/AV:N/AC:L'), '')
    assert.equal(calculateCvss('4.0', 'CVSS:4.0/AV:N/AC:L'), '')
    assert.equal(calculateCvss('3.1', 'not-a-vector'), '')
  })
})
