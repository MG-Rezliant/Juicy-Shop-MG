/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
// Modified by Rezilant AI, 2024-12-19 10:30:00 GMT, Added fs import for file existence validation
import fs = require('fs')

module.exports = function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2024-12-19 10:30:00 GMT, Implemented secure path handling with normalization, boundary checks, and file existence validation to prevent path traversal attacks
    // Define the base directory
    const QUARANTINE_BASE_DIR = path.resolve('ftp/quarantine/')
    
    // Sanitize and validate the file path
    const sanitizedFile = path.normalize(file).replace(/^(\.\.[\/\\])+/, '')
    const fullPath = path.resolve(QUARANTINE_BASE_DIR, sanitizedFile)
    
    // Ensure the resolved path is within the intended directory
    if (!fullPath.startsWith(QUARANTINE_BASE_DIR + path.sep)) {
      return res.status(403).send('Access denied')
    }
    
    // Verify file exists before sending
    if (!fs.existsSync(fullPath)) {
      return res.status(404).send('File not found')
    }
    
    res.sendFile(fullPath)

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('ftp/quarantine/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}