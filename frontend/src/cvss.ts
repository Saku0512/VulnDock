export type CvssVersion = '3.1' | '4.0'

type Metrics = Record<string, string>

export function calculateCvss(version: CvssVersion, vector: string): string {
  const metrics = parseVector(vector)
  if (!metrics) {
    return ''
  }

  if (metrics.CVSS === '3.1' || version === '3.1') {
    return calculateCvss31(metrics)
  }
  if (metrics.CVSS === '4.0' || version === '4.0') {
    return calculateCvss40(metrics)
  }
  return ''
}

export function inferCvssVersion(vector: string): CvssVersion | '' {
  const match = vector.trim().match(/^CVSS:(3\.1|4\.0)(?:\/|$)/i)
  return match ? match[1] as CvssVersion : ''
}

function parseVector(vector: string): Metrics | null {
  const trimmed = vector.trim()
  if (!trimmed) {
    return null
  }

  const metrics: Metrics = {}
  for (const part of trimmed.split('/')) {
    const separator = part.indexOf(':')
    if (separator < 0) {
      return null
    }
    const key = part.slice(0, separator).toUpperCase()
    const value = part.slice(separator + 1)
    if (!key || !value) {
      return null
    }
    metrics[key] = value
  }
  return metrics
}

function calculateCvss31(metrics: Metrics): string {
  const scope = metrics.S
  const values = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 }
  }

  const av = scoreValue(values.AV, metrics.AV)
  const ac = scoreValue(values.AC, metrics.AC)
  const ui = scoreValue(values.UI, metrics.UI)
  const c = scoreValue(values.CIA, metrics.C)
  const i = scoreValue(values.CIA, metrics.I)
  const a = scoreValue(values.CIA, metrics.A)
  const pr = scoreCvss31Privileges(metrics.PR, scope)

  if ([av, ac, ui, c, i, a, pr].some((value) => value === null) || !['U', 'C'].includes(scope)) {
    return ''
  }

  const impactSubScore = 1 - ((1 - c) * (1 - i) * (1 - a))
  const impact = scope === 'U'
    ? 6.42 * impactSubScore
    : 7.52 * (impactSubScore - 0.029) - 3.25 * Math.pow(impactSubScore - 0.02, 15)

  if (impact <= 0) {
    return '0.0'
  }

  const exploitability = 8.22 * av * ac * pr * ui
  const score = scope === 'U'
    ? roundUp1(Math.min(impact + exploitability, 10))
    : roundUp1(Math.min(1.08 * (impact + exploitability), 10))

  return score.toFixed(1)
}

function scoreCvss31Privileges(value: string, scope: string): number | null {
  if (value === 'N') {
    return 0.85
  }
  if (value === 'L') {
    return scope === 'C' ? 0.68 : scope === 'U' ? 0.62 : null
  }
  if (value === 'H') {
    return scope === 'C' ? 0.5 : scope === 'U' ? 0.27 : null
  }
  return null
}

function scoreValue<T extends string>(values: Record<T, number>, key: string): number | null {
  return Object.prototype.hasOwnProperty.call(values, key) ? values[key as T] : null
}

function roundUp1(value: number): number {
  return Math.ceil((value - Number.EPSILON) * 10) / 10
}

function calculateCvss40(rawMetrics: Metrics): string {
  const metrics = normalizeCvss40Metrics(rawMetrics)
  const required = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']
  if (!required.every((metric) => metrics[metric])) {
    return ''
  }

  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((metric) => m(metrics, metric) === 'N')) {
    return '0.0'
  }

  const macro = macroVector(metrics)
  const value = cvss40Lookup[macro]
  if (value === undefined) {
    return ''
  }

  const eq = macro.split('').map((valuePart) => Number(valuePart))
  const lowerScores = [
    cvss40Lookup[`${eq[0] + 1}${eq[1]}${eq[2]}${eq[3]}${eq[4]}${eq[5]}`],
    cvss40Lookup[`${eq[0]}${eq[1] + 1}${eq[2]}${eq[3]}${eq[4]}${eq[5]}`],
    lowerEq3Eq6Score(eq),
    cvss40Lookup[`${eq[0]}${eq[1]}${eq[2]}${eq[3] + 1}${eq[4]}${eq[5]}`],
    cvss40Lookup[`${eq[0]}${eq[1]}${eq[2]}${eq[3]}${eq[4] + 1}${eq[5]}`]
  ]

  const maxVector = findCvss40MaxVector(metrics, macro)
  if (!maxVector) {
    return ''
  }

  const distances = [
    distance(metrics, maxVector, ['AV', 'PR', 'UI']),
    distance(metrics, maxVector, ['AC', 'AT']),
    distance(metrics, maxVector, ['VC', 'VI', 'VA', 'CR', 'IR', 'AR']),
    distance(metrics, maxVector, ['SC', 'SI', 'SA']),
    0
  ]

  const maxSeverities = [
    cvss40MaxSeverity.eq1[eq[0]],
    cvss40MaxSeverity.eq2[eq[1]],
    cvss40MaxSeverity.eq3eq6[eq[2]][eq[5]],
    cvss40MaxSeverity.eq4[eq[3]],
    cvss40MaxSeverity.eq5[eq[4]]
  ].map((valuePart) => valuePart * 0.1)

  let existing = 0
  let normalized = 0
  for (let index = 0; index < lowerScores.length; index += 1) {
    const lowerScore = lowerScores[index]
    if (lowerScore === undefined || Number.isNaN(lowerScore)) {
      continue
    }
    existing += 1
    const severity = maxSeverities[index] === 0 ? 0 : distances[index] / maxSeverities[index]
    normalized += (value - lowerScore) * severity
  }

  const score = Math.max(0, Math.min(10, value - (existing === 0 ? 0 : normalized / existing)))
  return (Math.round(score * 10) / 10).toFixed(1)
}

function normalizeCvss40Metrics(rawMetrics: Metrics): Metrics {
  const metrics = { ...rawMetrics }
  for (const metric of ['E', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA']) {
    if (!metrics[metric]) {
      metrics[metric] = 'X'
    }
  }
  return metrics
}

function m(metrics: Metrics, metric: string): string {
  const selected = metrics[metric]
  if (metric === 'E' && selected === 'X') {
    return 'A'
  }
  if (['CR', 'IR', 'AR'].includes(metric) && selected === 'X') {
    return 'H'
  }
  const modified = metrics[`M${metric}`]
  if (modified && modified !== 'X') {
    return modified
  }
  return selected
}

function macroVector(metrics: Metrics): string {
  const eq1 = m(metrics, 'AV') === 'N' && m(metrics, 'PR') === 'N' && m(metrics, 'UI') === 'N'
    ? '0'
    : (m(metrics, 'AV') === 'N' || m(metrics, 'PR') === 'N' || m(metrics, 'UI') === 'N') && m(metrics, 'AV') !== 'P'
      ? '1'
      : '2'

  const eq2 = m(metrics, 'AC') === 'L' && m(metrics, 'AT') === 'N' ? '0' : '1'
  const eq3 = m(metrics, 'VC') === 'H' && m(metrics, 'VI') === 'H'
    ? '0'
    : ['VC', 'VI', 'VA'].some((metric) => m(metrics, metric) === 'H') ? '1' : '2'
  const eq4 = m(metrics, 'MSI') === 'S' || m(metrics, 'MSA') === 'S'
    ? '0'
    : ['SC', 'SI', 'SA'].some((metric) => m(metrics, metric) === 'H') ? '1' : '2'
  const eq5 = m(metrics, 'E') === 'A' ? '0' : m(metrics, 'E') === 'P' ? '1' : '2'
  const eq6 = (m(metrics, 'CR') === 'H' && m(metrics, 'VC') === 'H')
    || (m(metrics, 'IR') === 'H' && m(metrics, 'VI') === 'H')
    || (m(metrics, 'AR') === 'H' && m(metrics, 'VA') === 'H')
    ? '0'
    : '1'

  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`
}

function lowerEq3Eq6Score(eq: number[]): number | undefined {
  if (eq[2] === 0 && eq[5] === 0) {
    return Math.max(
      cvss40Lookup[`${eq[0]}${eq[1]}${eq[2]}${eq[3]}${eq[4]}${eq[5] + 1}`] ?? Number.NaN,
      cvss40Lookup[`${eq[0]}${eq[1]}${eq[2] + 1}${eq[3]}${eq[4]}${eq[5]}`] ?? Number.NaN
    )
  }
  if ((eq[2] === 1 && eq[5] === 1) || (eq[2] === 0 && eq[5] === 1)) {
    return cvss40Lookup[`${eq[0]}${eq[1]}${eq[2] + 1}${eq[3]}${eq[4]}${eq[5]}`]
  }
  if (eq[2] === 1 && eq[5] === 0) {
    return cvss40Lookup[`${eq[0]}${eq[1]}${eq[2]}${eq[3]}${eq[4]}${eq[5] + 1}`]
  }
  return cvss40Lookup[`${eq[0]}${eq[1]}${eq[2] + 1}${eq[3]}${eq[4]}${eq[5] + 1}`]
}

function findCvss40MaxVector(metrics: Metrics, macro: string): string {
  const eq1Maxes = cvss40MaxComposed.eq1[Number(macro[0])]
  const eq2Maxes = cvss40MaxComposed.eq2[Number(macro[1])]
  const eq3Eq6Maxes = cvss40MaxComposed.eq3[Number(macro[2])][macro[5]]
  const eq4Maxes = cvss40MaxComposed.eq4[Number(macro[3])]
  const eq5Maxes = cvss40MaxComposed.eq5[Number(macro[4])]

  for (const eq1 of eq1Maxes) {
    for (const eq2 of eq2Maxes) {
      for (const eq3Eq6 of eq3Eq6Maxes) {
        for (const eq4 of eq4Maxes) {
          for (const eq5 of eq5Maxes) {
            const candidate = eq1 + eq2 + eq3Eq6 + eq4 + eq5
            const ok = Object.keys(cvss40Levels).every((metric) => {
              const metricDistance = level(metric, m(metrics, metric)) - level(metric, extractMetric(candidate, metric))
              return metricDistance >= 0
            })
            if (ok) {
              return candidate
            }
          }
        }
      }
    }
  }
  return ''
}

function distance(metrics: Metrics, maxVector: string, metricNames: string[]): number {
  return metricNames.reduce((total, metric) => {
    return total + level(metric, m(metrics, metric)) - level(metric, extractMetric(maxVector, metric))
  }, 0)
}

function level(metric: string, value: string): number {
  return cvss40Levels[metric][value]
}

function extractMetric(vector: string, metric: string): string {
  const match = vector.match(new RegExp(`(?:^|/)${metric}:([^/]+)`))
  return match ? match[1] : ''
}

const cvss40Levels: Record<string, Record<string, number>> = {
  AV: { N: 0, A: 0.1, L: 0.2, P: 0.3 },
  PR: { N: 0, L: 0.1, H: 0.2 },
  UI: { N: 0, P: 0.1, A: 0.2 },
  AC: { L: 0, H: 0.1 },
  AT: { N: 0, P: 0.1 },
  VC: { H: 0, L: 0.1, N: 0.2 },
  VI: { H: 0, L: 0.1, N: 0.2 },
  VA: { H: 0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 },
  SI: { S: 0, H: 0.1, L: 0.2, N: 0.3 },
  SA: { S: 0, H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0, M: 0.1, L: 0.2 },
  IR: { H: 0, M: 0.1, L: 0.2 },
  AR: { H: 0, M: 0.1, L: 0.2 }
}

const cvss40MaxSeverity = {
  eq1: { 0: 1, 1: 4, 2: 5 },
  eq2: { 0: 1, 1: 2 },
  eq3eq6: {
    0: { 0: 7, 1: 6 },
    1: { 0: 8, 1: 8 },
    2: { 1: 10 }
  },
  eq4: { 0: 6, 1: 5, 2: 4 },
  eq5: { 0: 1, 1: 1, 2: 1 }
}

const cvss40MaxComposed = {
  eq1: {
    0: ['AV:N/PR:N/UI:N/'],
    1: ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
    2: ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/']
  },
  eq2: {
    0: ['AC:L/AT:N/'],
    1: ['AC:H/AT:N/', 'AC:L/AT:P/']
  },
  eq3: {
    0: {
      '0': ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
      '1': ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/']
    },
    1: {
      '0': ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
      '1': ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/']
    },
    2: {
      '1': ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/']
    }
  },
  eq4: {
    0: ['SC:H/SI:S/SA:S/'],
    1: ['SC:H/SI:H/SA:H/'],
    2: ['SC:L/SI:L/SA:L/']
  },
  eq5: {
    0: ['E:A/'],
    1: ['E:P/'],
    2: ['E:U/']
  }
}

const cvss40Lookup: Record<string, number> = {
  '000000': 10, '000001': 9.9, '000010': 9.8, '000011': 9.5, '000020': 9.5, '000021': 9.2,
  '000100': 10, '000101': 9.6, '000110': 9.3, '000111': 8.7, '000120': 9.1, '000121': 8.1,
  '000200': 9.3, '000201': 9, '000210': 8.9, '000211': 8, '000220': 8.1, '000221': 6.8,
  '001000': 9.8, '001001': 9.5, '001010': 9.5, '001011': 9.2, '001020': 9, '001021': 8.4,
  '001100': 9.3, '001101': 9.2, '001110': 8.9, '001111': 8.1, '001120': 8.1, '001121': 6.5,
  '001200': 8.8, '001201': 8, '001210': 7.8, '001211': 7, '001220': 6.9, '001221': 4.8,
  '002001': 9.2, '002011': 8.2, '002021': 7.2, '002101': 7.9, '002111': 6.9, '002121': 5,
  '002201': 6.9, '002211': 5.5, '002221': 2.7, '010000': 9.9, '010001': 9.7, '010010': 9.5,
  '010011': 9.2, '010020': 9.2, '010021': 8.5, '010100': 9.5, '010101': 9.1, '010110': 9,
  '010111': 8.3, '010120': 8.4, '010121': 7.1, '010200': 9.2, '010201': 8.1, '010210': 8.2,
  '010211': 7.1, '010220': 7.2, '010221': 5.3, '011000': 9.5, '011001': 9.3, '011010': 9.2,
  '011011': 8.5, '011020': 8.5, '011021': 7.3, '011100': 9.2, '011101': 8.2, '011110': 8,
  '011111': 7.2, '011120': 7, '011121': 5.9, '011200': 8.4, '011201': 7, '011210': 7.1,
  '011211': 5.2, '011220': 5, '011221': 3, '012001': 8.6, '012011': 7.5, '012021': 5.2,
  '012101': 7.1, '012111': 5.2, '012121': 2.9, '012201': 6.3, '012211': 2.9, '012221': 1.7,
  '100000': 9.8, '100001': 9.5, '100010': 9.4, '100011': 8.7, '100020': 9.1, '100021': 8.1,
  '100100': 9.4, '100101': 8.9, '100110': 8.6, '100111': 7.4, '100120': 7.7, '100121': 6.4,
  '100200': 8.7, '100201': 7.5, '100210': 7.4, '100211': 6.3, '100220': 6.3, '100221': 4.9,
  '101000': 9.4, '101001': 8.9, '101010': 8.8, '101011': 7.7, '101020': 7.6, '101021': 6.7,
  '101100': 8.6, '101101': 7.6, '101110': 7.4, '101111': 5.8, '101120': 5.9, '101121': 5,
  '101200': 7.2, '101201': 5.7, '101210': 5.7, '101211': 5.2, '101220': 5.2, '101221': 2.5,
  '102001': 8.3, '102011': 7, '102021': 5.4, '102101': 6.5, '102111': 5.8, '102121': 2.6,
  '102201': 5.3, '102211': 2.1, '102221': 1.3, '110000': 9.5, '110001': 9, '110010': 8.8,
  '110011': 7.6, '110020': 7.6, '110021': 7, '110100': 9, '110101': 7.7, '110110': 7.5,
  '110111': 6.2, '110120': 6.1, '110121': 5.3, '110200': 7.7, '110201': 6.6, '110210': 6.8,
  '110211': 5.9, '110220': 5.2, '110221': 3, '111000': 8.9, '111001': 7.8, '111010': 7.6,
  '111011': 6.7, '111020': 6.2, '111021': 5.8, '111100': 7.4, '111101': 5.9, '111110': 5.7,
  '111111': 5.7, '111120': 4.7, '111121': 2.3, '111200': 6.1, '111201': 5.2, '111210': 5.7,
  '111211': 2.9, '111220': 2.4, '111221': 1.6, '112001': 7.1, '112011': 5.9, '112021': 3,
  '112101': 5.8, '112111': 2.6, '112121': 1.5, '112201': 2.3, '112211': 1.3, '112221': 0.6,
  '200000': 9.3, '200001': 8.7, '200010': 8.6, '200011': 7.2, '200020': 7.5, '200021': 5.8,
  '200100': 8.6, '200101': 7.4, '200110': 7.4, '200111': 6.1, '200120': 5.6, '200121': 3.4,
  '200200': 7, '200201': 5.4, '200210': 5.2, '200211': 4, '200220': 4, '200221': 2.2,
  '201000': 8.5, '201001': 7.5, '201010': 7.4, '201011': 5.5, '201020': 6.2, '201021': 5.1,
  '201100': 7.2, '201101': 5.7, '201110': 5.5, '201111': 4.1, '201120': 4.6, '201121': 1.9,
  '201200': 5.3, '201201': 3.6, '201210': 3.4, '201211': 1.9, '201220': 1.9, '201221': 0.8,
  '202001': 6.4, '202011': 5.1, '202021': 2, '202101': 4.7, '202111': 2.1, '202121': 1.1,
  '202201': 2.4, '202211': 0.9, '202221': 0.4, '210000': 8.8, '210001': 7.5, '210010': 7.3,
  '210011': 5.3, '210020': 6, '210021': 5, '210100': 7.3, '210101': 5.5, '210110': 5.9,
  '210111': 4, '210120': 4.1, '210121': 2, '210200': 5.4, '210201': 4.3, '210210': 4.5,
  '210211': 2.2, '210220': 2, '210221': 1.1, '211000': 7.5, '211001': 5.5, '211010': 5.8,
  '211011': 4.5, '211020': 4, '211021': 2.1, '211100': 6.1, '211101': 5.1, '211110': 4.8,
  '211111': 1.8, '211120': 2, '211121': 0.9, '211200': 4.6, '211201': 1.8, '211210': 1.7,
  '211211': 0.7, '211220': 0.8, '211221': 0.2, '212001': 5.3, '212011': 2.4, '212021': 1.4,
  '212101': 2.4, '212111': 1.2, '212121': 0.5, '212201': 1, '212211': 0.3, '212221': 0.1
}
