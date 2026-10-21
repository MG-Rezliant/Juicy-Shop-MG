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
    // Modified by Rezilant AI, 2025-12-04 23:47:27 GMT, Fixed NoSQL injection by adding input validation and sanitization
    // Add validation to ensure orderId is in expected format
    const sanitizeOrderId = (input: string): string => {
      // Remove any MongoDB operators or special characters
      // Assuming orderId should be alphanumeric (adjust pattern as needed)
      const sanitized = input.replace(/[^a-zA-Z0-9-_]/g, '');
      
      // Validate format (example: expecting specific format like ORD-12345)
      if (!/^[a-zA-Z0-9-_]{1,50}$/.test(sanitized)) {
        throw new Error('Invalid order ID format');
      }
      
      return sanitized;
    };

    // Apply sanitization before query
    try {
      const sanitizedId = sanitizeOrderId(id);
      db.ordersCollection.find({ orderId: sanitizedId }).then((order: any) => {
        const result = utils.queryResultToJson(order)
        challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
        if (result.data[0] === undefined) {
          result.data[0] = { orderId: sanitizedId }
        }
        res.json(result)
      }, () => {
        res.status(400).json({ error: 'Wrong Param' })
      })
    } catch (error) {
      // Handle validation error appropriately
      res.status(400).json({ error: 'Invalid order ID' });
    }
    // Original Code
    // db.ordersCollection.find({ orderId: id }).then((order: any) => {
    //   const result = utils.queryResultToJson(order)
    //   challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
    //   if (result.data[0] === undefined) {
    //     result.data[0] = { orderId: id }
    //   }
    //   res.json(result)
    // }, () => {
    //   res.status(400).json({ error: 'Wrong Param' })
    // })
  }
}