/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import fs from 'fs'
import yaml from 'js-yaml'
import { getCodeChallenges } from '../lib/codingChallenges'
import * as accuracy from '../lib/accuracy'
import * as utils from '../lib/utils'
import * as path from 'path'

const challengeUtils = require('../lib/challengeUtils')

interface SnippetRequestBody {
  challenge: string
}

interface VerdictRequestBody {
  selectedLines: number[]
  key: string
}

const setStatusCode = (error: any) => {
  switch (error.name) {
    case 'BrokenBoundary':
      return 422
    default:
      return 200
  }
}

export const retrieveCodeSnippet = async (challengeKey: string) => {
  const codeChallenges = await getCodeChallenges()
  if (codeChallenges.has(challengeKey)) {
    return codeChallenges.get(challengeKey) ?? null
  }
  return null
}

exports.serveCodeSnippet = () => async (req: Request<SnippetRequestBody, Record<string, unknown>, Record<string, unknown>>, res: Response, next: NextFunction) => {
  try {
    const snippetData = await retrieveCodeSnippet(req.params.challenge)
    if (snippetData == null) {
      res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${req.params.challenge}` })
      return
    }
    res.status(200).json({ snippet: snippetData.snippet })
  } catch (error) {
    const statusCode = setStatusCode(error)
    res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) })
  }
}

export const retrieveChallengesWithCodeSnippet = async () => {
  const codeChallenges = await getCodeChallenges()
  return [...codeChallenges.keys()]
}

exports.serveChallengesWithCodeSnippet = () => async (req: Request, res: Response, next: NextFunction) => {
  const codingChallenges = await retrieveChallengesWithCodeSnippet()
  res.json({ challenges: codingChallenges })
}

export const getVerdict = (vulnLines: number[], neutralLines: number[], selectedLines: number[]) => {
  if (selectedLines === undefined) return false
  if (vulnLines.length > selectedLines.length) return false
  if (!vulnLines.every(e => selectedLines.includes(e))) return false
  const okLines = [...vulnLines, ...neutralLines]
  const notOkLines = selectedLines.filter(x => !okLines.includes(x))
  return notOkLines.length === 0
}

// Modified by Rezilant AI, 2026-05-22 19:46:30 GMT, Added secure file path validation to prevent path traversal attacks
// Define the safe base directory
const SAFE_BASE_DIR = path.resolve('./data/static/codefixes/')

// Validate and sanitize the key parameter
function getSafeFilePath(key: string): string | null {
  // 1. Remove any path traversal sequences
  const sanitizedKey = key.replace(/\.\./g, '').replace(/[\/\\]/g, '')
  
  // 2. Whitelist validation - only allow alphanumeric, hyphens, and underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(sanitizedKey)) {
    return null
  }
  
  // 3. Build the full path
  const fullPath = path.join(SAFE_BASE_DIR, `${sanitizedKey}.info.yml`)
  
  // 4. Verify the resolved path is still within the safe directory
  const resolvedPath = path.resolve(fullPath)
  if (!resolvedPath.startsWith(SAFE_BASE_DIR)) {
    return null
  }
  
  // 5. Verify file exists and is a file (not a directory)
  if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isFile()) {
    return null
  }
  
  return resolvedPath
}

exports.checkVulnLines = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key
  let snippetData
  try {
    snippetData = await retrieveCodeSnippet(key)
    if (snippetData == null) {
      res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${key}` })
      return
    }
  } catch (error) {
    const statusCode = setStatusCode(error)
    res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) })
    return
  }
  const vulnLines: number[] = snippetData.vulnLines
  const neutralLines: number[] = snippetData.neutralLines
  const selectedLines: number[] = req.body.selectedLines
  const verdict = getVerdict(vulnLines, neutralLines, selectedLines)
  let hint
  // Original Code - Vulnerable to path traversal, replaced with secure path validation
  // if (fs.existsSync('./data/static/codefixes/' + key + '.info.yml')) {
  //   const codingChallengeInfos = yaml.load(fs.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8'))
  // Modified by Rezilant AI, 2026-05-22 19:46:30 GMT, Using secure path validation function to prevent directory traversal
  const safePath = getSafeFilePath(key)
  if (safePath) {
    const codingChallengeInfos = yaml.load(fs.readFileSync(safePath, 'utf8'))
    if (codingChallengeInfos?.hints) {
      if (accuracy.getFindItAttempts(key) > codingChallengeInfos.hints.length) {
        if (vulnLines.length === 1) {
          hint = res.__('Line {{vulnLine}} is responsible for this vulnerability or security flaw. Select it and submit to proceed.', { vulnLine: vulnLines[0].toString() })
        } else {
          hint = res.__('Lines {{vulnLines}} are responsible for this vulnerability or security flaw. Select them and submit to proceed.', { vulnLines: vulnLines.toString() })
        }
      } else {
        const nextHint = codingChallengeInfos.hints[accuracy.getFindItAttempts(key) - 1] // -1 prevents after first attempt
        if (nextHint) hint = res.__(nextHint)
      }
    }
  }
  if (verdict) {
    await challengeUtils.solveFindIt(key)
    res.status(200).json({
      verdict: true
    })
  } else {
    accuracy.storeFindItVerdict(key, false)
    res.status(200).json({
      verdict: false,
      hint
    })
  }
}