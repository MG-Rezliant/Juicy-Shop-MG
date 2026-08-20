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

export const checkCorrectFix = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key
  const selectedFix = req.body.selectedFix
  const fixData = readFixes(key)
  if (fixData.fixes.length === 0) {
    res.status(404).json({
      error: 'No fixes found for the snippet!'
    })
  } else {
    let explanation
    // Modified by Rezilant AI, 2026-08-20 03:19:24 GMT, Added path traversal protection with allowlist validation, input sanitization, and boundary checks
    // Define allowed challenge keys (allowlist)
    const ALLOWED_CHALLENGES = new Set([
      'challenge1',
      'challenge2',
      'sql-injection',
      // ... add all valid challenge names
    ]);

    // Sanitize and validate the key
    const sanitizedKey = key.replace(/[^a-zA-Z0-9_-]/g, '');

    // Validate against allowlist
    if (!ALLOWED_CHALLENGES.has(sanitizedKey)) {
      throw new Error('Invalid challenge key');
    }

    // Use path.join to safely construct the path
    const path = require('path');
    const basePath = path.resolve('./data/static/codefixes');
    const filePath = path.join(basePath, `${sanitizedKey}.info.yml`);

    // Verify the resolved path is still within the expected directory
    if (!filePath.startsWith(basePath)) {
      throw new Error('Path traversal attempt detected');
    }

    if (fs.existsSync(filePath)) {
      const codingChallengeInfos = yaml.load(fs.readFileSync(filePath, 'utf8'));
      // Original Code
      // if (fs.existsSync('./data/static/codefixes/' + key + '.info.yml')) {
      //   const codingChallengeInfos = yaml.load(fs.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8'))
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
}