/*
 * Copyright c 2014-2024 Bjoern Kimminich  the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from config
import * as utils from ../utils
import  Server  from socket.io
import  notifications, challenges  from ../../data/datacache
import * as challengeUtils from ../challengeUtils
import * as security from ../insecurity

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis  
  io: SocketIOClientStati