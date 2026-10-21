/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import fs = require('fs')

module.exports = function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-09-03 15:22:58 GMT, Added input validation with path canonicalization to prevent path traversal vulnerability
    // Define the base directory for encryption keys
    const KEYS_DIR = path.resolve('encryptionkeys/')
    
    // Whitelist allowed characters (alphanumeric, hyphen, underscore, dot)
    const SAFE_FILENAME_REGEX = /^[a-zA-Z0-9._-]+$/
    
    // Step 1: Validate filename format
    if (!SAFE_FILENAME_REGEX.test(file)) {
      res.status(400)
      return next(new Error('Invalid filename'))
    }
    
    // Step 2: Resolve the full path
    const requestedPath = path.resolve(KEYS_DIR, file)
    
    // Step 3: Ensure the resolved path is within the intended directory
    if (!requestedPath.startsWith(KEYS_DIR + path.sep)) {
      res.status(403)
      return next(new Error('Access denied'))
    }
    
    // Step 4: Check if file exists before sending
    if (!fs.existsSync(requestedPath)) {
      res.status(404)
      return next(new Error('File not found'))
    }
    
    // Safe to send the file
    res.sendFile(requestedPath)

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('encryptionkeys/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}