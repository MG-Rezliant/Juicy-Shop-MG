/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import fs = require('fs')

module.exports = function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-06-20 17:25:27 GMT, Added path traversal prevention with input validation and canonicalization
    // Define the allowed directory
    const LOGS_DIR = path.resolve('logs/');

    // Validate and sanitize the file parameter - Remove any directory traversal sequences
    const sanitizedFile = path.basename(file);
    const fullPath = path.resolve(LOGS_DIR, sanitizedFile);

    // Verify the resolved path is within the intended directory
    if (!fullPath.startsWith(LOGS_DIR + path.sep)) {
      return res.status(403).send('Access denied');
    }

    // Optional: Check if file exists before sending - prevents information disclosure
    if (!fs.existsSync(fullPath)) {
      return res.status(404).send('File not found');
    }

    res.sendFile(fullPath);

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('logs/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}