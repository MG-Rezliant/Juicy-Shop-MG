import { type NextFunction, type Request, type Response } from 'express'
import * as accuracy from '../lib/accuracy'

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

export const readFixes = (key: string) => {
  if (CodeFixes[key]) {
    return CodeFixes[key]
  }
  const files = fs.readdirSync(FixesDir)
  const fixes: string[] = []
  let correct: number = -1
  for (const file of files) {
    if (file.startsWith(`${key}_`)) {
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

  CodeFixes[key] = {
    fixes,
    correct
  }
  return CodeFixes[key]
}

interface FixesRequestParams {
  key: string
}

interface VerdictRequestBody {
  key: string
  selectedFix: number
}

export const serveCodeFixes = () => (req: Request<FixesRequestParams, Record<string, unknown>, Record<string, unknown>>, res: Response, next: NextFunction) => {
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
}

// @rezliant RZ-54007018 · 2026-11-03 — Prevents path traversal in filesystem operations
export const checkCorrectFix = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key
  const sanitizedKey = key.replace(/[^a-zA-Z0-9_-]/g, '')
  const selectedFix = req.body.selectedFix
  const fixData = readFixes(sanitizedKey)
  if (fixData.fixes.length === 0) {
    res.status(404).json({
      error: 'No fixes found for the snippet!'
    })
  } else {
    let explanation
    if (fs.existsSync('./data/static/codefixes/' + sanitizedKey + '.info.yml')) {
      const codingChallengeInfos = yaml.load(fs.readFileSync('./data/static/codefixes/' + sanitizedKey + '.info.yml', 'utf8'))
      const selectedFixInfo = codingChallengeInfos?.fixes.find(({ id }: { id: number }) => id === selectedFix + 1)
      if (selectedFixInfo?.explanation) explanation = res.__(selectedFixInfo.explanation)
    }
    if (selectedFix === fixData.correct) {
      await challengeUtils.solveFixIt(sanitizedKey)
      res.status(200).json({
        verdict: true,
        explanation
      })
    } else {
      accuracy.storeFixItVerdict(sanitizedKey, false)
      res.status(200).json({
        verdict: false,
        explanation
      })
    }
  }
}

/*
 * @rezliant-change-log:start
 * RZ-54007018 · 2026-11-03 · Path traversal via unsanitized key parameter in filesystem operations
 * Change: Added input sanitization using regex allowlist to remove all characters except alphanumerics, underscores, and hyphens
 * Benefit: Prevents directory traversal sequences from escaping intended directory boundary
 * Scope: checkCorrectFix function
 * 
 * Rezliant remediation history: 1 total · 1 most recent shown
 * @rezliant-change-log:end
 */