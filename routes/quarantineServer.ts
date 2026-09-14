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

    // @rezliant RZ-51250626 · 2026-09-14 — Prevents path traversal on Windows via consistent separator normalization
    // 2. Resolve the full path
    const requestedPath = path.resolve(QUARANTINE_DIR, file)

    // Normalize path separators for cross-platform path traversal prevention
    const normalizedRequested = requestedPath.split(path.sep).join('/')
    const normalizedQuarantine = QUARANTINE_DIR.split(path.sep).join('/')

    // 3. Canonicalize and verify the path stays within quarantine directory
    if (!normalizedRequested.startsWith(normalizedQuarantine)) {
      res.status(403)
      return next(new Error('Access denied'))
    }

    // 4. Verify file exists before sending
    if (!fs.existsSync(requestedPath)) {
      res.status(404)
      return next(new Error('File not found'))
    }

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
@rezliant-change-log:start
RZ-51250626 · 2026-09-14 · Path traversal vulnerability via Windows backslash bypass
Change: Added path separator normalization before boundary check
Benefit: Prevents path traversal on Windows via consistent separator normalization
Scope: serveQuarantineFiles request handler

RZ-XXXXXXX · 2026-09-04 · Path traversal vulnerability in file parameter
Change: Implemented path traversal prevention with input validation, path canonicalization, and directory boundary check
Benefit: Blocks directory traversal attempts before file access
Scope: serveQuarantineFiles request handler

Rezliant remediation history: 2 total · 2 most recent shown
@rezliant-change-log:end
*/