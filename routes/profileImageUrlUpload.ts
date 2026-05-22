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
              // Modified by Rezilant AI, 2026-05-22 19:45:29 GMT, Fix path traversal vulnerability by implementing strict input validation and safe file path construction
              import path from 'path';
              
              // Define allowed file extensions
              const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif'];
              const UPLOAD_DIR = path.resolve('frontend/dist/frontend/assets/public/images/uploads');
              
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              
              // Sanitize and validate the extension
              const sanitizedExt = ext.toLowerCase().replace(/[^a-z0-9]/g, '');
              
              // Validate extension against whitelist
              if (!ALLOWED_EXTENSIONS.includes(sanitizedExt)) {
                  throw new Error('Invalid file extension');
              }
              
              // Use path.join to safely construct the file path and prevent traversal
              const userId = String(loggedInUser.data.id).replace(/[^0-9]/g, '');
              const fileName = `${userId}.${sanitizedExt}`;
              const safePath = path.join(UPLOAD_DIR, fileName);
              
              // Verify the resolved path is within the intended directory
              if (!safePath.startsWith(UPLOAD_DIR)) {
                  throw new Error('Invalid file path');
              }
              
              // Now safely write the file
              imageRequest.pipe(fs.createWriteStream(safePath));
              
              // Original Code
              // const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              // imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${userId}.${sanitizedExt}` }) }).catch((error: Error) => { next(error) })
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