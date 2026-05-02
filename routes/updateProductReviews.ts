/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import { ObjectId } from 'mongodb' // Modified by Rezilant AI: Added import for ObjectId validation

const security = require('../lib/insecurity')

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    // Modified by Rezilant AI, 2026-05-02 15:14:39 GMT, Added ObjectId validation to prevent NoSQL injection attacks
    // Validate that the ID is a valid ObjectId format
    if (!ObjectId.isValid(req.body.id)) {
      return res.status(400).json({ error: 'Invalid ID format' });
    }
    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
      // Original Code
      // { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
      { _id: new ObjectId(req.body.id) }, // Modified by Rezilant AI: Use ObjectId constructor to sanitize user input and prevent query operator injection
      { $set: { message: req.body.message } },
      { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
    ).then(
      (result: { modified: number, original: Array&lt;{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge