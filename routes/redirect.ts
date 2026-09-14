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
  return ({ query, protocol, get }: Request, res: Response, next: NextFunction) => {
    // @rezliant RZ-2D8A2E55 · 2026-09-14 — Prevents open redirect to untrusted domains
    const ALLOWED_REDIRECTS: { [key: string]: string } = {
      'home': '/',
      'products': '/products',
      'crypto-dash': 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
      'crypto-bitcoin': 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
      'crypto-eth': 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
    }
    
    const APPROVED_DOMAINS = [
      'explorer.dash.org',
      'blockchain.info',
      'etherscan.io'
    ]
    
    const redirectKey = query.to as string
    const safeUrl = ALLOWED_REDIRECTS[redirectKey]
    
    if (!safeUrl) {
      res.status(400)
      next(new Error('Invalid redirect key'))
      return
    }
    
    try {
      const parsedUrl = new URL(safeUrl, `${protocol}://${get('host')}`)
      const isRelative = !parsedUrl.host || parsedUrl.host === get('host')
      const isApprovedDomain = APPROVED_DOMAINS.includes(parsedUrl.hostname)
      
      if (!isRelative && !isApprovedDomain) {
        res.status(403)
        next(new Error('Redirect to untrusted domain blocked'))
        return
      }
      
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { 
        return safeUrl.includes('explorer.dash.org') || 
               safeUrl.includes('blockchain.info') || 
               safeUrl.includes('etherscan.io')
      })
      
      res.redirect(safeUrl)
    } catch (error) {
      res.status(400)
      next(new Error('Invalid URL format'))
    }
  }
}

/*
@rezliant-change-log:start
RZ-2D8A2E55 · 2026-09-14 · Open redirect vulnerability at line 60
Change: Replaced allowlist implementation with comprehensive domain validation using key-based lookup and inline domain checking with request context for relative URLs
Benefit: Prevents redirect to untrusted domains through defense-in-depth validation
Scope: performRedirect function

Rezliant remediation history: 1 total · 1 most recent shown
@rezliant-change-log:end
*/