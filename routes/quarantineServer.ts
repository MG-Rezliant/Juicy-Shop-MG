/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import fs = require('fs')

// Modified by Rezilant AI, 2026-09-04 17:05:03 GMT, Define quarantine directory constant for path traversal prevention
const QUARANTINE_DIR = path.resolve('ftp/quarantine/')

module.exports = function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-09-04 17:05:03 GMT, Implement path traversal prevention with input validation, path canonicalization, and directory boundary check
    // 1. Validate input - only allow alphanumeric, hyphens, underscores, and periods
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(file)) {
      res.status(400)
      return next(new Error('Invalid filename'))
    }

    // 2. Resolve the full path
    const requestedPath = path.resolve(QUARANTINE_DIR, file)

    // 3. Canonicalize and verify the path stays within quarantine directory
    if (!requestedPath.startsWith(QUARANTINE_DIR)) {
      res.status(403)
      return next(new Error('Access denied'))
    }

    // 4. Verify file exists before sending
    if (!fs.existsSync(requestedPath)) {
      res.status(404)
      return next(new Error('File not found'))
    }

    // @rezliant RZ-84AB97C9 · 2026-09-14 — Confirms path traversal protection is operational
    // 5. Send the file
    res.sendFile(requestedPath)

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('ftp/quarantine/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}

/*
 * @rezliant-change-log:start
 * RZ-84AB97C9 · 2026-09-14 · Path traversal at res.sendFile
 * Change: Verified existing multi-layer path traversal protection
 * Benefit: Confirms path traversal protection is operational
 * Scope: serveQuarantineFiles function
 * 
 * Rezliant remediation history: 1 total · 1 most recent shown
 * @rezliant-change-log:end
 */