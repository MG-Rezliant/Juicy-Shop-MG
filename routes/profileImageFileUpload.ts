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
// Modified by Rezilant AI, 2026-08-20 02:57:27 GMT, Added path module for secure file path handling
import * as path from 'path'

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
          // Modified by Rezilant AI, 2026-08-20 02:57:27 GMT, Added secure file path validation to prevent path traversal attacks
          // Define a safe upload directory
          const UPLOAD_DIR = path.resolve(__dirname, '../frontend/dist/frontend/assets/public/images/uploads')

          // Validate the file extension against an allowlist
          const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif']
          if (!ALLOWED_EXTENSIONS.includes(uploadedFileType.ext.toLowerCase())) {
            res.status(415)
            next(new Error('Invalid file type'))
            return
          }

          // Sanitize the user ID (ensure it contains only alphanumeric characters)
          const sanitizedUserId = String(loggedInUser.data.id).replace(/[^a-zA-Z0-9]/g, '')

          // Construct the safe file path
          const fileName = `${sanitizedUserId}.${uploadedFileType.ext}`
          const safePath = path.join(UPLOAD_DIR, fileName)

          // Verify the resolved path is still within the upload directory (prevents path traversal)
          if (!safePath.startsWith(UPLOAD_DIR)) {
            res.status(400)
            next(new Error('Invalid file path'))
            return
          }

          fs.open(safePath, 'w', function (err, fd) {
            if (err != null) logger.warn('Error opening file: ' + err.message)
            // @ts-expect-error FIXME buffer has unexpected type
            fs.write(fd, buffer, 0, buffer.length, null, function (err) {
              if (err != null) logger.warn('Error writing file: ' + err.message)
              fs.close(fd, function () { })
            })
          })
          // Original Code
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