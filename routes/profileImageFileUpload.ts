/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import logger from '../lib/logger'

import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const fileType = require('file-type')

module.exports = function fileUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file
    const buffer = file?.buffer
    const uploadedFileType = await fileType.fromBuffer(buffer)

    if (uploadedFileType === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
    } else {
      if (uploadedFileType !== null && utils.startsWith(uploadedFileType.mime, 'image')) {
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
        if (loggedInUser) {
          // Modified by Rezilant AI, 2026-05-22 19:45:28 GMT, Fix for path traversal vulnerability - sanitize inputs and validate file paths
          // Import path module for secure file path construction
          import * as path from 'path';
          
          // Define a safe base directory (absolute path)
          const UPLOAD_BASE_DIR = path.resolve(__dirname, '../frontend/dist/frontend/assets/public/images/uploads');
          
          // Sanitize and validate inputs - remove dangerous characters from user ID and extension
          const sanitizedUserId = loggedInUser.data.id.toString().replace(/[^a-zA-Z0-9_-]/g, '');
          const sanitizedExtension = uploadedFileType.ext.toLowerCase().replace(/[^a-z0-9]/g, '');
          
          // Construct the filename
          const filename = `${sanitizedUserId}.${sanitizedExtension}`;
          
          // Build the full path and verify it stays within the base directory
          const fullPath = path.resolve(UPLOAD_BASE_DIR, filename);
          
          // Security check: Ensure the resolved path is within the allowed directory
          if (!fullPath.startsWith(UPLOAD_BASE_DIR + path.sep)) {
              throw new Error('Invalid file path detected');
          }
          
          // Additional validation: whitelist allowed extensions
          const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif'];
          if (!ALLOWED_EXTENSIONS.includes(sanitizedExtension)) {
              throw new Error('File type not allowed');
          }
          
          // Safe file operation using validated path
          fs.open(fullPath, 'w', function (err, fd) {
            if (err != null) logger.warn('Error opening file: ' + err.message)
            // @ts-expect-error FIXME buffer has unexpected type
            fs.write(fd, buffer, 0, buffer.length, null, function (err) {
              if (err != null) logger.warn('Error writing file: ' + err.message)
              fs.close(fd, function () { })
            })
          })
          
          // Original Code - Vulnerable to path traversal attacks
          // fs.open(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}`, 'w', function (err, fd) {
          //   if (err != null) logger.warn('Error opening file: ' + err.message)
          //   // @ts-expect-error FIXME buffer has unexpected type
          //   fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          //     if (err != null) logger.warn('Error writing file: ' + err.message)
          //     fs.close(fd, function () { })
          //   })
          // })
          UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
            if (user != null) {
              return await user.update({ profileImage: `assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}` })
            }
          }).catch((error: Error) => {
            next(error)
          })
          res.location(process.env.BASE_PATH + '/profile')
          res.redirect(process.env.BASE_PATH + '/profile')
        } else {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        }
      } else {
        res.status(415)
        next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`))
      }
    }
  }
}