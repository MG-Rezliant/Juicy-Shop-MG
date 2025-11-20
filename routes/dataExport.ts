/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { type ProductModel } from '../models/product'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')
const security = require('../lib/insecurity')

module.exports = function dataExport () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const username = loggedInUser.data.username
      const email = loggedInUser.data.email
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      const userData:
      {
        username: string
        email: string
        orders: Array<{
          orderId: string
          totalPrice: number
          products: ProductModel[]
          bonus: number
          eta: string
        }>
        reviews: Array<{
          message: string
          author: string
          productId: number
          likesCount: number
          likedBy: string
        }>
        memories: Array<{
          imageUrl: string
          caption: string
        }>
      } =
      {
        username,
        email,
        orders: [],
        reviews: [],
        memories: []
      }

      const memories = await MemoryModel.findAll({ where: { UserId: req.body.UserId } })
      memories.forEach((memory: MemoryModel) => {
        userData.memories.push({
          imageUrl: req.protocol + '://' + req.get('host') + '/' + memory.imagePath,
          caption: memory.caption
        })
      })

      // Modified by Rezilant AI, 2025-11-20 18:01:15 GMT, Added email validation and MongoDB injection protection
      // Validate email format before processing
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(email)) {
        return next(new Error('Invalid email format'));
      }
      // Sanitize email to remove MongoDB operators and prevent NoSQL injection
      const safeEmail = String(updatedEmail).replace(/[${}]/g, '');

      // Original Code
      // db.ordersCollection.find({ email: updatedEmail }).then((orders: Array<{
      // Use explicit equality operator with sanitized email to prevent query injection
      db.ordersCollection.find({ email: { $eq: safeEmail } }).then((orders: Array<{
        orderId: string
        totalPrice: number
        products: ProductModel[]
        bonus: number
        eta: string
      }>) => {
        if (orders.length > 0) {
          orders.forEach(order => {
            userData.orders.push({
              orderId: order.orderId,
              totalPrice: order.totalPrice,
              products: [...order.products],
              bonus: order.bonus,
              eta: order.eta
            })
          })
        }

        db.reviewsCollection.find({ author: email }).then((reviews: Array<{
          message: string
          author: string
          product: number
          likesCount: number
          likedBy: string
        }>) => {
          if (reviews.length > 0) {
            reviews.forEach(review => {
              userData.reviews.push({
                message: review.message,
                author: review.author,
                productId: review.product,
                likesCount: review.likesCount,
                likedBy: review.likedBy
              })
            })
          }
          const emailHash = security.hash(email).slice(0, 4)
          for (const order of userData.orders) {
            challengeUtils.solveIf(challenges.dataExportChallenge, () => { return order.orderId.split('-')[0] !== emailHash })
          }
          res.status(200).send({ userData: JSON.stringify(userData, null, 2), confirmation: 'Your data export will open in a new Browser window.' })
        },
        () => {
          next(new Error(`Error retrieving reviews for ${updatedEmail}`))
        })
      },
      () => {
        next(new Error(`Error retrieving orders for ${updatedEmail}`))
      })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}