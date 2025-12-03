/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import { ObjectId } from 'mongodb' // Modified by Rezilant AI, 2025-12-03 22:21:18 GMT, Added import for ObjectId validation

const security = require('../lib/insecurity')

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    
    // Modified by Rezilant AI, 2025-12-03 22:21:18 GMT, Added ObjectId validation to prevent NoSQL injection
    let reviewId: ObjectId
    try {
      if (!req.body.id || typeof req.body.id !== 'string') {
        return res.status(400).json({ error: 'Invalid review ID format' })
      }
      reviewId = new ObjectId(req.body.id)
    } catch (err) {
      return res.status(400).json({ error: 'Invalid review ID format' })
    }
    
    // Original Code
    // db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
    //   { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
    //   { $set: { message: req.body.message } },
    //   { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
    // ).then(
    db.reviewsCollection.update( // Modified by Rezilant AI, 2025-12-03 22:21:18 GMT, Using validated ObjectId and disabled multi-update
      { _id: reviewId },
      { $set: { message: req.body.message } },
      { multi: false }
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