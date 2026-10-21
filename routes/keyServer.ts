/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
// Modified by Rezilant AI, 2026-08-20 02:56:08 GMT, Added fs import for secure file validation
import fs = require('fs')

module.exports = function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-08-20 02:56:08 GMT, Added path traversal protection with canonicalization, boundary checks, and file validation
    // Define the allowed directory
    const ENCRYPTION_KEYS_DIR = path.resolve('encryptionkeys/')
    
    // Validate and sanitize the file input - removes any path components
    const sanitizedFile = path.basename(file)
    const resolvedPath = path.resolve(ENCRYPTION_KEYS_DIR, sanitizedFile)
    
    // Ensure the resolved path is within the intended directory
    if (!resolvedPath.startsWith(ENCRYPTION_KEYS_DIR + path.sep)) {
      res.status(400)
      return next(new Error('Invalid file path'))
    }
    
    // Additional validation: Check if file exists and is a file (not a directory)
    if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isFile()) {
      res.status(404)
      return next(new Error('File not found'))
    }
    
    // Safe to send the file
    res.sendFile(resolvedPath)

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('encryptionkeys/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}