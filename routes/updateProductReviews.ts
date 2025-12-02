/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    // Modified by Rezilant AI, 2025-12-02 14:52:42 GMT, Sanitize input to prevent NoSQL injection by validating and sanitizing the ID
    // Sanitize the ID - ensure it's a valid ObjectId or string
    const sanitizedId = String(req.body.id).replace(/[^a-zA-Z0-9]/g, '')
    
    // Better: Use strict type checking for ObjectId
    if (!sanitizedId || sanitizedId.length !== 24) {
      return res.status(400).json({ error: 'Invalid review ID' })
    }
    // Original Code
    // db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
    //   { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
    //   { $set: { message: req.body.message } },
    //   { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
    // ).then(
    db.reviewsCollection.update(
      { _id: sanitizedId }, // Modified: Now safe from operator injection
      { $set: { message: req.body.message } },
      { multi: false } // Modified: Should only update ONE review
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge