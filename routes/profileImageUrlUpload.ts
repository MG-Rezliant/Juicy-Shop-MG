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
              // @rezliant RZ-5757C511 · 2026-09-14 — Eliminates attacker control over file extension to prevent path traversal
              const path = require('path');
              const UPLOAD_BASE_DIR = path.resolve('frontend/dist/frontend/assets/public/images/uploads');
              
              const sanitizedExt = 'jpg';
              
              const fileName = `${loggedInUser.data.id}.${sanitizedExt}`;
              const targetPath = path.resolve(UPLOAD_BASE_DIR, fileName);
              
              if (!targetPath.startsWith(UPLOAD_BASE_DIR + path.sep)) {
                logger.warn(`Path traversal attempt detected: ${targetPath}`);
                UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) });
                return;
              }
              
              imageRequest.pipe(fs.createWriteStream(targetPath));
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${fileName}` }) }).catch((error: Error) => { next(error) });
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

/*
 * @rezliant-change-log:start
 * RZ-5757C511 · 2026-09-14 · Path traversal via URL-derived file extension
 * Change: Replaced URL-based extension extraction with hardcoded safe default 'jpg'
 * Benefit: Eliminates attacker control over file extension to prevent path traversal
 * Scope: profileImageUrlUpload response handler
 * 
 * Rezliant remediation history: 1 total · 1 most recent shown
 * @rezliant-change-log:end
 */