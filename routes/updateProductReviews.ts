/*
 * Copyright c 2014-2024 Bjoern Kimminich  the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require../lib/challengeUtils
import  type Request, type Response, type NextFunction  from express
import * as db from ../data/mongodb
import  challenges  from ../data/datacache

const security = require../lib/insecurity

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews  