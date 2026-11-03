import { type NextFunction, type Request, type Response } from 'express'
import * as accuracy from '../lib/accuracy'
import path from 'path'

const challengeUtils = require('../lib/challengeUtils')
const fs = require('fs')
const yaml = require('js-yaml')

const FixesDir = 'data/static/codefixes'

interface codeFix {
  fixes: string[]
  correct: number
}

type cache = Record<string, codeFix>

const CodeFixes: cache = {}

// @rezliant RZ-F6A71F23 · 2026-11-03 — Prevents path traversal attacks via unsanitized key parameter
const sanitizeKey = (key: string): string => {
  const sanitized = key.replace(/[^a-zA-Z0-9_-]/g, '')
  if (sanitized !== key || key.includes('..') || key.includes('/') || key.includes('\\')) {
    throw new Error('Invalid key parameter')
  }
  return sanitized
}

export const readFixes = (key: string) => {
  const safeKey = sanitizeKey(key)
  
  if (CodeFixes[safeKey]) {
    return CodeFixes[safeKey]
  }
  const files = fs.readdirSync(FixesDir)
  const fixes: string[] = []
  let correct: number = -1
  for (const file of files) {
    if (file.startsWith(`${safeKey}_`)) {
      const fix = fs.readFileSync(`${FixesDir}/${file}`).toString()
      const metadata = file.split('_')
      const number = metadata[1]
      fixes.push(fix)
      if (metadata.length === 3) {
        correct = parseInt(number, 10)
        correct--
      }
    }
  }

  CodeFixes[safeKey] = {
    fixes,
    correct
  }
  return CodeFixes[safeKey]
}

interface FixesRequestParams {
  key: string
}

interface VerdictRequestBody {
  key: string
  selectedFix: number
}

export const serveCodeFixes = () => (req: Request<FixesRequestParams, Record<string, unknown>, Record<string, unknown>>, res: Response, next: NextFunction) => {
  try {
    const key = req.params.key
    const fixData = readFixes(key)
    if (fixData.fixes.length === 0) {
      res.status(404).json({
        error: 'No fixes found for the snippet!'
      })
      return
    }
    res.status(200).json({
      fixes: fixData.fixes
    })
  } catch (error) {
    res.status(400).json({
      error: 'Invalid key parameter'
    })
  }
}

export const checkCorrectFix = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  try {
    const key = req.body.key
    const selectedFix = req.body.selectedFix
    const fixData = readFixes(key)
    if (fixData.fixes.length === 0) {
      res.status(404).json({
        error: 'No fixes found for the snippet!'
      })
    } else {
      let explanation
      const safeKey = sanitizeKey(key)
      const infoPath = path.join('.', 'data', 'static', 'codefixes', `${safeKey}.info.yml`)
      if (fs.existsSync(infoPath)) {
        const codingChallengeInfos = yaml.load(fs.readFileSync(infoPath, 'utf8'))
        const selectedFixInfo = codingChallengeInfos?.fixes.find(({ id }: { id: number }) => id === selectedFix + 1)
        if (selectedFixInfo?.explanation) explanation = res.__(selectedFixInfo.explanation)
      }
      if (selectedFix === fixData.correct) {
        await challengeUtils.solveFixIt(key)
        res.status(200).json({
          verdict: true,
          explanation
        })
      } else {
        accuracy.storeFixItVerdict(key, false)
        res.status(200).json({
          verdict: false,
          explanation
        })
      }
    }
  } catch (error) {
    res.status(400).json({
      error: 'Invalid key parameter'
    })
  }
}

// @rezliant-change-log:start
// RZ-F6A71F23 · 2026-11-03 · Path traversal via unsanitized key parameter in file path construction
// Change: Added sanitizeKey validation function, imported path module, wrapped route handlers in try-catch blocks
// Benefit: Prevents directory traversal attacks by validating and sanitizing user-supplied key values
// Scope: sanitizeKey function, readFixes function, serveCodeFixes export, checkCorrectFix export
//
// Rezliant remediation history: 1 total · 1 most recent shown
// @rezliant-change-log:end