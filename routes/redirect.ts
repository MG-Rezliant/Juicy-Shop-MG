/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

module.exports = function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    // const toUrl: string = query.to as string
    // Modified by Rezilant AI, 2025-11-24 15:40:49 GMT, Implemented strict allowlist with key-based lookup to prevent open redirect vulnerability
    // Define strict allowlist of permitted redirect URLs
    const ALLOWED_REDIRECTS: { [key: string]: string } = {
      'home': '/',
      'products': '/products',
      'crypto-dash': 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
      'crypto-bitcoin': 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
      'crypto-eth': 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
    }
    
    // Use key-based lookup instead of URL validation
    const redirectKey = query.to as string
    const safeUrl = ALLOWED_REDIRECTS[redirectKey]
    
    if (safeUrl) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { 
        return safeUrl.includes('explorer.dash.org') || 
               safeUrl.includes('blockchain.info') || 
               safeUrl.includes('etherscan.io')
      })
      res.redirect(safeUrl)
    } else {
      res.status(400)
      next(new Error('Invalid redirect key: ' + redirectKey))
    }
    // Original Code
    // if (security.isRedirectAllowed(toUrl)) {
    //   challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
    //   challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
    //   res.redirect(toUrl)
    // } else {
    //   res.status(406)
    //   next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    // }
  }
}

//function isUnintendedRedirect (toUrl: string) {
//  let unintended = true
//  for (const allowedUrl of security.redirectAllowlist) {
//    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
//  }
//  return unintended
//}
