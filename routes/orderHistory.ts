/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ordersCollection } from '../data/mongodb'

const security = require('../lib/insecurity')

module.exports.orderHistory = function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      // Modified by Rezilant AI, 2025-11-24 15:56:49 GMT, Added type validation and $eq operator to prevent NoSQL injection
      // Validate that email is a string (not an object with operators)
      if (typeof email !== 'string') {
        return next(new Error('Invalid email format'))
      }
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      // Ensure updatedEmail is treated as a plain string value
      const order = await ordersCollection.find({ 
        email: { $eq: updatedEmail } 
      })
      // Original Code
      // const updatedEmail = email.replace(/[aeiou]/gi, '*')
      // const order = await ordersCollection.find({ email: updatedEmail })
      res.status(200).json({ status: 'success', data: order })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

module.exports.allOrders = function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const order = await ordersCollection.find()
    res.status(200).json({ status: 'success', data: order.reverse() })
  }
}

module.exports.toggleDeliveryStatus = function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    await ordersCollection.update({ _id: req.params.id }, { $set: { delivered: deliveryStatus, eta } })
    res.status(200).json({ status: 'success' })
  }
}