/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-08-20 02:56:34 GMT, Prevent path traversal by sanitizing file path and validating it stays within quarantine directory
    // Define the base directory
    const QUARANTINE_DIR = path.resolve('ftp/quarantine/')

    // Sanitize and validate the file parameter - removes any directory traversal sequences
    const sanitizedFile = path.basename(file)
    const resolvedPath = path.resolve(QUARANTINE_DIR, sanitizedFile)

    // Ensure the resolved path is still within the quarantine directory
    if (!resolvedPath.startsWith(QUARANTINE_DIR)) {
      res.status(403)
      return next(new Error('Access denied'))
    }

    // Send the file
    res.sendFile(resolvedPath)

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('ftp/quarantine/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}