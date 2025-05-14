import * as core from '@actions/core'
import * as fs from 'fs'

//import { RlJsonReportProcessor } from './rlJsonReportProcessor'
// Debug logs are only output if the `ACTIONS_STEP_DEBUG` secret is true

/*
// parse the rl-json report and produce a simplefied summary on stdout
//
// extensive data lists can be embedded in a details html construct:
// <details><summary>summary</summary> extensive content ... </details>
// drop down behaviour will work in github markdown text
//
// for the moment console.log is sufficient to print to stdout
*/

function Capitalize(str: string): string {
  const modStr = str[0].toUpperCase() + str.slice(1)
  return modStr
}

type ODictByString = {
  [key: string]: object
}

export class RlJsonReportProcessor {
  filename: string
  data: ODictByString

  name: string
  purl: string

  assessments: ODictByString // report/metadata.assessments
  violations: ODictByString // report.metadata.violations
  components: ODictByString // report.metadata.components
  vulnerabilities: ODictByString // report.metadata.vulnerabilities

  viols: string[]
  indent: string = '    '
  out: string[]

  constructor(filename: string) {
    this.filename = filename
    this.viols = []
    this.out = []
    this.data = JSON.parse(fs.readFileSync(this.filename, 'utf-8'))

    this.name =
      this.jpath2string(this.data, 'report.info.file.name') || '<no name>'
    this.purl =
      this.jpath2string(this.data, 'report.info.file.identity.purl') ||
      '<no purl>'

    this.assessments = this.jpath2dict(this.data, 'report.metadata.assessments')
    this.violations = this.jpath2dict(this.data, 'report.metadata.violations')
    this.components = this.jpath2dict(this.data, 'report.metadata.components')
    this.vulnerabilities = this.jpath2dict(
      this.data,
      'report.metadata.vulnerabilities'
    )
  }

  jpath2string(data: ODictByString, path_str: string): string {
    const path_list: string[] = path_str.split('.')
    let z: ODictByString = data
    for (const item of path_list) {
      z = data[item] as ODictByString // the last item is actually a string
    }
    const u = z as unknown
    return u as string
  }

  jpath2string_list(data: ODictByString, path_str: string): string[] {
    const path_list: string[] = path_str.split('.')
    let z: ODictByString = data
    for (const item of path_list) {
      z = data[item] as ODictByString // the last item is actually a string
    }
    const u = z as unknown
    return u as string[]
  }

  jpath2number(data: ODictByString, path_str: string): number {
    const path_list: string[] = path_str.split('.')
    let z: ODictByString = data
    for (const item of path_list) {
      z = data[item] as ODictByString // the last item is actually a string
    }
    const u = z as unknown
    return u as number
  }

  jpath2dict(data: ODictByString, path_str: string): ODictByString {
    const path_list: string[] = path_str.split('.')
    let z: ODictByString = data
    for (const item of path_list) {
      z = data[item] as ODictByString // the last item is actually a string
    }
    return z
  }

  cveSeverity(baseScore: number): string {
    /*
     * Severity	BaseScore
     * None	    0
     * Low	    0.1-3.9
     * Medium	  4.0-6.9
     * High	    7.0-8.9
     * Critical	9.0-10.0
     */
    if (baseScore < 0.1) {
      return 'None'
    }
    if (baseScore >= 0.1 && baseScore < 4.0) {
      return 'Low'
    }
    if (baseScore >= 4.0 && baseScore < 7.0) {
      return 'Medium'
    }
    if (baseScore >= 7.0 && baseScore < 9.0) {
      return 'High'
    }
    if (baseScore >= 9.0 && baseScore <= 10.0) {
      return 'Critical'
    }

    return 'Critical'
  }

  output(): void {
    for (const line of this.out) {
      console.log(line)
    }
  }

  htmlDetails(
    summary: string,
    content: string[],
    plain: boolean = false
  ): void {
    if (plain == true) {
      this.out.push(`<a name="${summary}">${summary}</a>`)
      for (const line of content) {
        this.out.push(line)
      }
      this.out.push('')
      return
    }

    this.out.push(`<a name="${summary}"></a>`)
    this.out.push('<details>')
    this.out.push(`<summary>${summary}</summary>`)

    for (const line of content) {
      this.out.push(line)
    }

    this.out.push('</details>')
    this.out.push('')
  }

  colorStatus(status: string): string {
    if (status == 'Fail') {
      status = ':red_square: ' + status
    }
    if (status == 'Warning') {
      status = ':orange_square: ' + status
    }
    if (status == 'Pass') {
      status = ':green_square: ' + status
    }
    return status
  }

  colorSeverity(severity: string): string {
    if (severity == 'Critical') {
      severity = ':red_circle: ' + severity
    }
    if (severity == 'High') {
      severity = ':orange_circle: ' + severity
    }
    if (severity == 'Medium') {
      severity = ':yellow_circle: ' + severity
    }
    if (severity == 'Low') {
      severity = ':large_blue_circle: ' + severity
    }
    if (severity == 'None') {
      severity = ':green_circle: ' + severity
    }
    return severity
  }

  getVulnerabilityInfo(cve: string): string[] {
    const lines: string[] = []

    const url: string = `https://www.cve.org/CVERecord?id=${cve}`
    const baseScore = this.jpath2number(
      this.vulnerabilities,
      'cve.cvss.baseScore'
    )
    let severity: string = this.cveSeverity(baseScore)
    severity = this.colorSeverity(severity)

    lines.push(
      `- [${cve}](${url}); Severity: ${severity}, base-score: ${baseScore}`
    )

    return lines
  }

  getComponentInfo(component_id: string): string[] {
    const lines: string[] = []

    const component = this.jpath2dict(this.components, 'component_id')
    const name = this.jpath2string(component, 'name')
    const path = this.jpath2string(component, 'path')
    const version = this.jpath2string(component, 'identity.version')
    const purl = this.jpath2string(component, 'identity.purl')

    const vuls = this.jpath2dict(component, 'identity.vulnerabilities')
    let cve_list: string[] = []
    if (vuls) {
      cve_list = this.jpath2string_list(vuls, 'active')
    }

    lines.push('### Component:')
    lines.push('')
    lines.push(`- Path: ${path}`)

    if (purl.length > 0) {
      lines.push(`- Purl: ${purl}`)
    } else {
      lines.push(`- Name: ${name}`)
      lines.push(`- Version: ${version}`)
    }
    lines.push('')

    if (cve_list.length > 0) {
      lines.push('#### Vulnerabilities:')
      for (const cve of cve_list) {
        const z: string[] = this.getVulnerabilityInfo(cve)
        for (const line of z) {
          lines.push(line)
        }
      }
      lines.push('')
    }

    return lines
  }

  getViolationInfo(viol: string): string[] {
    const rr: string[] = []

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for (const [_, vv] of Object.entries(this.violations)) {
      let v = vv as ODictByString

      if (this.jpath2string(v, 'rule_id') != viol) {
        continue
      }
      const description = this.jpath2string(v, 'description')
      const category = this.jpath2string(v, 'category')
      const component_ids = this.jpath2string_list(v, 'references.component')

      let severity: string = Capitalize(this.jpath2string(v, 'severity'))
      severity = this.colorSeverity(severity)
      let status: string = Capitalize(this.jpath2string(v, 'status'))
      status = this.colorStatus(status)

      rr.push('')
      rr.push(`- **Description:** ***${description}***`)
      rr.push(`- **Category: ${category}**`)
      rr.push(`- **Status: ${status}**`)
      rr.push(`- **Severity: ${severity}**`)

      rr.push('')

      for (const id of component_ids) {
        for (const line of this.getComponentInfo(id)) {
          rr.push(line)
        }
      }
    }
    return rr
  }

  showViolations(): void {
    this.out.push('')
    this.out.push('## Violations')
    this.out.push('')

    const vv: string[] = this.viols.sort()
    for (const viol of vv) {
      let lines: string[] = []
      lines = this.getViolationInfo(viol)
      this.htmlDetails(viol, lines)
    }
  }

  // ------------------------------------------
  doAllViolations(viols: string[]): string {
    const zz: string[] = []

    if (viols.length > 0) {
      for (const viol of viols) {
        if (this.viols.includes(viol) === false) {
          this.viols.push(viol)
        }
      }
      for (const viol of viols) {
        zz.push(`[${viol}](#${viol})`)
      }
    }

    let z: string = ''
    if (zz.length > 0) {
      z = ' (' + zz.join(', ') + ')'
    }

    return z
  }

  doOneAssesementLine(
    status: string,
    count: number,
    label: string,
    viols: string[]
  ): string {
    const z: string = this.doAllViolations(viols)

    status = this.colorStatus(status)
    let line: string = `${status}: ${label}` + z
    if (count > 0) {
      line = `${status}: ${label}: ${count}` + z
    }
    return line
  }

  do_one_evalu(item: ODictByString): [number, string] {
    const prio: number = this.jpath2number(item, 'priority')
    const count: number = this.jpath2number(item, 'count')

    const status: string = Capitalize(this.jpath2string(item, 'status'))
    const label: string = Capitalize(this.jpath2string(item, 'label'))

    const viols: string[] = this.jpath2string_list(item, 'violations')

    const line: string = this.doOneAssesementLine(status, count, label, viols)

    const r: [number, string] = [prio, line]
    return r
  }

  do_all_evalu(evaluations: object[]): string[] {
    /*
     * evaluations have a priority,
     * sort by prio most important (0) first
     */
    const lines_by_prio: { [key: number]: string[] } = {}

    for (const item of evaluations) {
      let i = item as ODictByString

      const [prio, s] = this.do_one_evalu(i)
      if (lines_by_prio[prio] == undefined) {
        lines_by_prio[prio] = []
      }
      lines_by_prio[prio].push(s)
    }

    const lines: string[] = []
    for (const prio in lines_by_prio) {
      for (const line of lines_by_prio[prio]) {
        lines.push(line)
      }
    }

    return lines
  }

  doEvaluations(v: ODictByString): void {
    const evaluations = v['evaluations'] as ODictByString[]

    if (evaluations.length > 0) {
      const ss: string[] = this.do_all_evalu(evaluations)
      for (const s of ss) {
        this.out.push(`${this.indent}- ${s}`)
      }
    }
  }

  doOneAssessment(k: string, v: ODictByString): void {
    let line: string = `- ${Capitalize(k)}:`
    this.out.push(line)

    const count: number = this.jpath2number(v, 'count')

    const label: string = Capitalize(this.jpath2string(v, 'label'))
    const status: string = Capitalize(this.jpath2string(v, 'status'))

    const viols: string[] = this.jpath2string_list(v, 'violations')

    line = this.doOneAssesementLine(status, count, label, viols)
    this.out.push(`${this.indent}- ${line}`)

    this.doEvaluations(v)
  }

  doAssessments(): void {
    this.out.push('')
    this.out.push('# Assessments')
    this.out.push('')

    for (const [k, v] of Object.entries(this.assessments)) {
      let i = v as ODictByString
      this.doOneAssessment(k, i)
    }
  }

  simplifyRlJson(): void {
    this.doAssessments()
    this.showViolations()
  }
}

/*
const rjrp = new RlJsonReportProcessor("report.rl.json");
rjrp.simplifyRlJson();
rjrp.output();
*/

/**
 * The main function for the action.
 *
 * @returns Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const rl_json_file: string = core.getInput('rl_json_path')
    const data = JSON.parse(fs.readFileSync(rl_json_file, 'utf-8'))
    core.debug(`loaded json file ${rl_json_file}`)
    core.debug(new Date().toTimeString())

    const name: string = data.info.file.identity.name
    const purl: string = data.info.file.identity.purl
    core.debug(`name: ${name}, purl: ${purl}`)

    const rjrp = new RlJsonReportProcessor('report.rl.json')
    rjrp.simplifyRlJson()
    rjrp.output()

    // Set outputs for other workflow steps to use
    // core.setOutput('time', new Date().toTimeString())
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) {
      core.setFailed(error.message)
    }
  }
}
