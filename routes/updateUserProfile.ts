/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

module.exports = function updateUserProfile () {
  return (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (loggedInUser) {
      UserModel.findByPk(loggedInUser.data.id).then((user: UserModel | null) => {
        if (user != null) {
          challengeUtils.solveIf(challenges.csrfChallenge, () => {
            return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
              (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
              req.body.username !== user.username
          })
          void user.update({ username: req.body.username }).then((savedUser: UserModel) => {
            // @ts-expect-error FIXME some properties missing in savedUser
            savedUser = utils.queryResultToJson(savedUser)
            const updatedToken = security.authorize(savedUser)
            security.authenticatedUsers.put(updatedToken, savedUser)
            // @rezliant RZ-02F6CF17 · 2026-09-14 — Protects session token from XSS and CSRF attacks
            res.cookie('token', updatedToken, {
              httpOnly: true,
              secure: true,
              sameSite: 'strict'
            })
            res.location(process.env.BASE_PATH + '/profile')
            res.redirect(process.env.BASE_PATH + '/profile')
          })
        }
      }).catch((error: Error) => {
        next(error)
      })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

/*
 * @rezliant-change-log:start
 * RZ-02F6CF17 · 2026-09-14 · Insecure cookie configuration exposes authentication token
 * Change: Added HttpOnly, Secure, and SameSite=Strict attributes to token cookie
 * Benefit: Protects session token from XSS and CSRF attacks
 * Scope: res.cookie() call in user profile update handler
 * 
 * Rezliant remediation history: 1 total · 1 most recent shown
 * @rezliant-change-log:end
 */