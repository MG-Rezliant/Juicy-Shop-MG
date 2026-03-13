/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
// Modified by Rezilant AI, 2026-03-13 15:18:32 GMT, Added ObjectId import for NoSQL injection prevention
import { ObjectId } from 'mongodb'

const security = require('../lib/insecurity')

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Modified by Rezilant AI, 2026-03-13 15:18:32 GMT, Added validation for MongoDB ObjectId to prevent NoSQL injection
    if (!ObjectId.isValid(req.body.id)) {
      return res.status(400).json({ error: 'Invalid ID format' })
    }
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    // Modified by Rezilant AI, 2026-03-13 15:18:32 GMT, Using validated ObjectId instead of raw input to prevent NoSQL injection
    const query = { _id: new ObjectId(req.body.id) }
    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
      // Original Code
      // { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
      query,
      { $set: { message: req.body.message } },
      { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
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