/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
// Modified by Rezilant AI, 2026-08-20 02:56:08 GMT - Added fs import for file validation
import fs = require('fs')

module.exports = function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-08-20 02:56:08 GMT - Fixed path traversal vulnerability by implementing path sanitization and validation
    // Define the allowed logs directory
    const LOGS_DIR = path.resolve('logs/')
    
    // Validate and sanitize the file parameter - Remove any directory components
    const sanitizedFile = path.basename(file)
    const resolvedPath = path.resolve(LOGS_DIR, sanitizedFile)
    
    // Verify the resolved path is still within the logs directory
    if (!resolvedPath.startsWith(LOGS_DIR + path.sep)) {
      res.status(403)
      return next(new Error('Access denied'))
    }
    
    // Check file exists and is a file (not a directory)
    if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isFile()) {
      res.status(404)
      return next(new Error('File not found'))
    }
    
    res.sendFile(resolvedPath)
    
    // Original Code - Path traversal vulnerability: insufficient validation allows directory traversal
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('logs/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}