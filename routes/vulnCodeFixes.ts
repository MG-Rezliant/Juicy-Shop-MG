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

// @rezliant RZ-54D5730E · 2026-11-03 — Blocks path traversal in code fix loading
const sanitizeKey = (key: string): string | null => {
  if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
    return null
  }
  return path.basename(key)
}

export const readFixes = (key: string) => {
  const sanitizedKey = sanitizeKey(key)
  if (!sanitizedKey) {
    return { fixes: [], correct: -1 }
  }
  
  if (CodeFixes[sanitizedKey]) {
    return CodeFixes[sanitizedKey]
  }
  const files = fs.readdirSync(FixesDir)
  const fixes: string[] = []
  let correct: number = -1
  for (const file of files) {
    if (file.startsWith(`${sanitizedKey}_`)) {
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

  CodeFixes[sanitizedKey] = {
    fixes,
    correct
  }
  return CodeFixes[sanitizedKey]
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

export const checkCorrectFix = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key
  const sanitizedKey = sanitizeKey(key)
  if (!sanitizedKey) {
    res.status(400).json({
      error: 'Invalid key parameter'
    })
    return
  }
  
  const selectedFix = req.body.selectedFix
  const fixData = readFixes(sanitizedKey)
  if (fixData.fixes.length === 0) {
    res.status(404).json({
      error: 'No fixes found for the snippet!'
    })
  } else {
    let explanation
    const infoPath = path.join('./data/static/codefixes', `${sanitizedKey}.info.yml`)
    if (fs.existsSync(infoPath)) {
      const codingChallengeInfos = yaml.load(fs.readFileSync(infoPath, 'utf8'))
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

// @rezliant-change-log:start
// RZ-54D5730E · 2026-11-03 · Path traversal in code fix file loading
// Change: Added sanitizeKey() validation with alphanumeric allowlist and path.basename(); applied sanitization in readFixes() and checkCorrectFix(); replaced string concatenation with path.join()
// Benefit: Blocks path traversal in code fix loading
// Scope: sanitizeKey function, readFixes function, checkCorrectFix function
//
// Rezliant remediation history: 1 total · 1 most recent shown
// @rezliant-change-log:end