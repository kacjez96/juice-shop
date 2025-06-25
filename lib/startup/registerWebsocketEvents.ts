/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import config from 'config'
import * as utils from '../utils'
import { Server } from 'socket.io'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: SocketIOClientStatic & Server
}

const registerWebsocketEvents = (server: any) => {
  // Bezpieczna konfiguracja Socket.io
  const io = new Server(server, {
    cors: {
      origin: function (origin: string | undefined, callback: any) {
        const allowedOrigins = [
          'http://localhost:3000',
          'http://localhost:4200',
          'http://172.18.0.2:3000',
          'http://172.18.0.2:4200'
        ]
        
        // Zezwól na połączenia bez origin (same-origin)
        if (!origin) return callback(null, true)
        
        if (allowedOrigins.includes(origin)) {
          callback(null, true)
        } else {
          console.warn(`WebSocket CORS: Blocked connection from origin: ${origin}`)
          callback(new Error('Not allowed by CORS'))
        }
      },
      credentials: true,
      methods: ["GET", "POST"]
    },
    // Ważne: wyłącz session ID w URL
    cookie: {
      name: "io",
      httpOnly: true,
      sameSite: "strict"
    },
    // Używaj tylko bezpiecznych transportów
    transports: ['websocket', 'polling']
  })

  // @ts-expect-error FIXME Type safety issue when setting global socket-io object
  globalWithSocketIO.io = io

  io.on('connection', (socket: any) => {
    // Logowanie dla debugowania (możesz usunąć w produkcji)
    console.log(`New WebSocket connection: ${socket.id}`)
    
    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    notifications.forEach((notification: any) => {
      socket.emit('challenge solved', notification)
    })

    socket.on('notification received', (data: any) => {
      const i = notifications.findIndex(({ flag }: any) => flag === data)
      if (i > -1) {
        notifications.splice(i, 1)
      }
    })

    socket.on('verifyLocalXssChallenge', (data: any) => {
      // Dodaj podstawową walidację
      if (typeof data !== 'string' || data.length > 1000) {
        return
      }
      
      challengeUtils.solveIf(challenges.localXssChallenge, () => { 
        return utils.contains(data, '<iframe src="javascript:alert(`xss`)">') 
      })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { 
        return utils.contains(data, config.get('challenges.xssBonusPayload')) 
      })
    })

    socket.on('verifySvgInjectionChallenge', (data: any) => {
      // Dodaj podstawową walidację
      if (typeof data !== 'string' || data.length > 500) {
        return
      }
      
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { 
        return data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placecats.com\/(g\/)?[\d]+\/[\d]+.*/) && 
               security.isRedirectAllowed(data) 
      })
    })

    socket.on('verifyCloseNotificationsChallenge', (data: any) => {
      // Dodaj podstawową walidację
      if (!Array.isArray(data) || data.length > 100) {
        return
      }
      
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { 
        return Array.isArray(data) && data.length > 1 
      })
    })

    // Obsługa rozłączenia
    socket.on('disconnect', (reason: string) => {
      console.log(`WebSocket disconnected: ${socket.id}, reason: ${reason}`)
    })
  })
}

export default registerWebsocketEvents