/*
 * Copyright c 2014-2024 Bjoern Kimminich  the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import  type Request, type Response, type NextFunction  from express
import  ordersCollection  from ../data/mongodb

const security = require../lib/insecurity

module.exports.orderHistory = function orderHistory  
  return async req: Request, res: Response, next: NextFunction = 
    const loggedInUser = security.authenticatedUsers.getreq.headers?.authorizat