/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from 'src/environments/environment'
import { Injectable, NgZone } from '@angular/core'
import { io, type Socket } from 'socket.io-client'

@Injectable({
  providedIn: 'root'
})
export class SocketIoService {
  private _socket: Socket

  constructor (private readonly ngZone: NgZone) {
    this.ngZone.runOutsideAngular(() => {
      // Konfiguracja Socket.io z wymuszeniem bezpiecznych opcji
      const socketOptions = {
        withCredentials: true, // Ważne! Wysyłaj cookies
        transports: ['websocket', 'polling'], // Preferuj WebSocket
        // Wyłącz automatyczne dołączanie parametrów do URL
        autoConnect: true,
        // Nie dodawaj żadnych parametrów query które mogłyby zawierać session ID
        query: {}
      }

      if (environment.hostServer === '.') {
        this._socket = io(window.location.origin, {
          ...socketOptions,
          path: (window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/') + 'socket.io'
        })
      } else {
        this._socket = io(environment.hostServer, socketOptions)
      }

      // Dodaj obsługę błędów połączenia
      this._socket.on('connect_error', (error) => {
        console.error('Socket.io connection error:', error.message)
      })

      this._socket.on('connect', () => {
        console.log('Socket.io connected successfully')
      })
    })
  }

  socket () {
    return this._socket
  }
}