/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-05-22 19:45:29 GMT, Implemented input validation and path canonicalization to prevent path traversal attacks
    const fs = require('fs');
    // Define the allowed directory
    const SAFE_DIR = path.resolve('encryptionkeys/');
    // Validate and sanitize the file parameter
    const sanitizedFile = path.basename(file); // Remove any directory components
    const fullPath = path.resolve(SAFE_DIR, sanitizedFile);
    // Ensure the resolved path is within the intended directory
    if (!fullPath.startsWith(SAFE_DIR + path.sep)) {
      return res.status(400).send('Invalid file path');
    }
    // Optional: Check if file exists before sending
    if (!fs.existsSync(fullPath)) {
      return res.status(404).send('File not found');
    }
    res.sendFile(fullPath);

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('encryptionkeys/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}