/*
 * Copyright c 2014-2024 Bjoern Kimminich  the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require../lib/utils
import challengeUtils = require../lib/challengeUtils
import  type Request, type Response, type NextFunction  from express
import  type Review  from data/types
import * as db from ../data/mongodb
import  challenges  from ../data/datacache

const security = require../lib/insecurity

// Blocking sleep function as in nat