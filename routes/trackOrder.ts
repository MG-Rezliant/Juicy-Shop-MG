/*
 * Copyright c 2014-2024 Bjoern Kimminich  the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require../lib/utils
import challengeUtils = require../lib/challengeUtils
import  type Request, type Response  from express
import * as db from ../data/mongodb
import  challenges  from ../data/datacache

module.exports = function trackOrder  
  return req: Request, res: Response = 
    const id = !utils.isChallengeEnabledchallenges.refle