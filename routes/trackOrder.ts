/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

module.exports = function trackOrder () {
  return (req: Request, res: Response) => {
    const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : req.params.id

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    // Modified by Rezilant AI, 2026-08-20 02:54:44 GMT, Fixed NoSQL injection by using explicit $eq operator with sanitized input
    // Validate and sanitize the input
    const sanitizedId = String(id).replace(/[^a-zA-Z0-9-_]/g, '');
    // Use strict type matching with explicit $eq operator
    db.ordersCollection.find({ 
      orderId: { $eq: sanitizedId } 
    }).then((order: any) => {
    // Original Code - Vulnerable to NoSQL injection via implicit equality matching
    // db.ordersCollection.find({ orderId: id }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}