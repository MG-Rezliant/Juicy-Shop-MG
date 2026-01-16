/*
 * Copyright c 2014-2024 Bjoern Kimminich  the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from fs/promises
import  type Request, type Response, type NextFunction  from express
import  type User  from ../data/types
import  UserModel  from ../models/user
import jwt,  type JwtPayload, type VerifyErrors  from jsonwebtoken
import challengeUtils = require../lib/challengeUtils
import logger from ../lib/logger
import config from config
i