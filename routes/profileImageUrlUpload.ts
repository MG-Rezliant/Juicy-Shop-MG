/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')

module.exports = function profileImageUrlUpload () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const imageRequest = request
          .get(url)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              // Modified by Rezilant AI, 2026-08-20 02:58:09 GMT, Fixed Path Traversal vulnerability by adding input validation, sanitization, and secure path construction
              import path from 'path';
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              
              // 1. Whitelist allowed extensions
              const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif'];
              const sanitizedExt = ext.toLowerCase().replace(/[^a-z0-9]/g, '');

              // 2. Validate extension
              if (!ALLOWED_EXTENSIONS.includes(sanitizedExt)) {
                  throw new Error('Invalid file extension');
              }

              // 3. Sanitize user ID (ensure it's alphanumeric)
              const sanitizedUserId = String(loggedInUser.data.id).replace(/[^a-zA-Z0-9_-]/g, '');

              // 4. Use path.join() to safely construct the file path
              const uploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads');
              const filename = `${sanitizedUserId}.${sanitizedExt}`;
              const filepath = path.join(uploadDir, filename);

              // 5. Verify the resolved path is still within the intended directory
              if (!filepath.startsWith(uploadDir)) {
                  throw new Error('Invalid file path');
              }

              imageRequest.pipe(fs.createWriteStream(filepath))
              // Original Code
              // const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              // imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
            } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}