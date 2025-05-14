import * as core from '@actions/core'
// import { wait } from './wait.js'
import fs from 'fs'

// Debug logs are only output if the `ACTIONS_STEP_DEBUG` secret is true

/**
 * The main function for the action.
 *
 * @returns Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    // const ms: string = core.getInput('milliseconds')
    const rl_json_file: string = core.getInput('rl_json_file')
    const data = JSON.parse(fs.readFileSync(rl_json_file, 'utf-8'))
    core.debug(`loaded json file ${rl_json_file}`)
    core.debug(new Date().toTimeString())

    const name: string = data.info.file.identity.name
    const purl: string = data.info.file.identity.purl
    core.debug(`name: {name}, purl: {purl}`)

    // data.info.file.identity {name, purl }
    // data.report.metadata.assessments

    // Set outputs for other workflow steps to use
    core.setOutput('time', new Date().toTimeString())
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
