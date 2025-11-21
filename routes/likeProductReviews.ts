/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import { ObjectId } from 'mongodb'

const security = require('../lib/insecurity')

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Modified by Rezilant AI, 2025-11-21 12:54:58 GMT, Added input validation and sanitization to prevent NoSQL injection by validating ObjectId format
    const id = req.body.id
    
    // Validate that id is a string and a valid MongoDB ObjectId
    if (typeof id !== 'string' || !ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid ID format' })
    }
    
    // Convert to ObjectId to prevent injection
    const objectId = new ObjectId(id)
    // Original Code
    // const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    db.reviewsCollection.findOne({ _id: objectId }).then((review: Review) => {
      if (!review) {
        res.status(404).json({ error: 'Not found' })
      } else {
        const likedBy = review.likedBy
        if (!likedBy.includes(user.data.email)) {
          db.reviewsCollection.update(
            { _id: objectId },
            { $inc: { likesCount: 1 } }
          ).then(
            () => {
              // Artificial wait for timing attack challenge
              setTimeout(function () {
                db.reviewsCollection.findOne({ _id: objectId }).then((review: Review) => {
                  const likedBy = review.likedBy
                  likedBy.push(user.data.email)
                  let count = 0
                  for (let i = 0; i < likedBy.length; i++) {
                    if (likedBy[i] === user.data.email) {
                      count++
                    }
                  }
                  challengeUtils.solveIf(challenges.timingAttackChallenge, () => { return count > 2 })
                  db.reviewsCollection.update(
                    { _id: objectId },
                    { $set: { likedBy } }
                  ).then(
                    (result: any) => {
                      res.json(result)
                    }, (err: unknown) => {
                      res.status(500).json(err)
                    })
                }, () => {
                  res.status(400).json({ error: 'Wrong Params' })
                })
              }, 150)
            }, (err: unknown) => {
              res.status(500).json(err)
            })
        } else {
          res.status(403).json({ error: 'Not allowed' })
        }
      }
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}