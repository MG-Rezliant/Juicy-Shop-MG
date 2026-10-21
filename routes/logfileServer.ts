/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-06-03 22:17:09 GMT, Added path traversal protection with canonicalization and directory boundary validation
    const logsDirectory = path.resolve('logs/')
    // Canonicalize the requested path
    const requestedPath = path.resolve(logsDirectory, file)
    // Validate that the resolved path is within the logs directory
    if (!requestedPath.startsWith(logsDirectory + path.sep)) {
      res.status(403)
      return next(new Error('Access denied'))
    }
    // Optional: Additional validation - only allow specific file extensions
    const allowedExtensions = ['.log', '.txt']
    if (!allowedExtensions.some(ext => requestedPath.endsWith(ext))) {
      res.status(403)
      return next(new Error('Invalid file type'))
    }
    // Verify file exists and is a file (not a directory)
    if (!fs.existsSync(requestedPath) || !fs.statSync(requestedPath).isFile()) {
      res.status(404)
      return next(new Error('File not found'))
    }
    res.sendFile(requestedPath)

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('logs/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}