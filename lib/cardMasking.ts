/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'

const luhn = (n: string) => [...n].reverse().reduce((s, d, i) => {
  let x = Number(d); if (i % 2) { x *= 2; if (x > 9) x -= 9 } return s + x
}, 0) % 10 === 0

export const maskPan = (pan: string) => '*'.repeat(12) + pan.slice(-4)

/** PCI-DSS 3.4: validate the PAN, then replace it with a masked value before it is persisted. */
export function maskCardNumber () {
  return (req: Request, res: Response, next: NextFunction) => {
    const pan = String(req.body?.cardNum ?? '').replace(/\D/g, '')
    if (pan.length !== 16 || !luhn(pan)) {
      res.status(400).json({ status: 'error', message: 'Invalid card number' })
      return
    }
    req.body.cardNum = maskPan(pan)
    next()
  }
}
