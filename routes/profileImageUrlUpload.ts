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
        // Modified by Rezilant AI, 2026-09-04 16:56:38 GMT, Added SSRF protection with URL validation, allowlist, and private IP blocking
        // Add URL validation imports and helper function
        const { URL } = require('url');
        
        // Define allowed domains/protocols
        const ALLOWED_DOMAINS = [
          'cdn.example.com',
          'images.example.com',
          'secure-storage.example.com'
        ];
        
        const ALLOWED_PROTOCOLS = ['https:'];
        
        // Validation function
        function isUrlSafe(urlString: string): boolean {
          try {
            const parsedUrl = new URL(urlString);
            
            // Check protocol
            if (!ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
              return false;
            }
            
            // Check domain against allowlist
            if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
              return false;
            }
            
            // Prevent access to private IP ranges
            const hostname = parsedUrl.hostname;
            if (
              hostname === 'localhost' ||
              hostname === '127.0.0.1' ||
              hostname.startsWith('10.') ||
              hostname.startsWith('172.16.') ||
              hostname.startsWith('192.168.') ||
              hostname.startsWith('169.254.')
            ) {
              return false;
            }
            
            return true;
          } catch (error) {
            return false;
          }
        }
        
        // Validate URL before proceeding
        if (!isUrlSafe(url)) {
          return res.status(400).json({ 
            error: 'Invalid or disallowed URL' 
          });
        }
        
        // Original Code
        // const imageRequest = request
        const imageRequest = request
          .get(url)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
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