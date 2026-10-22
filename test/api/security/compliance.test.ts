import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import { createTestApp } from '../helpers/setup'
import { login } from '../helpers/auth'

let app: Express
let sequelize: Sequelize

before(async () => {
  ({ app, sequelize } = await createTestApp())
}, { timeout: 90000 })

void describe('Security-as-Code regulatory assertions (TDS)', () => {
  // PCI-DSS 3.4 : PAN must be unreadable wherever it is stored or returned
  void it('PCI-DSS 3.4: card creation neither returns nor stores the full PAN', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app).post('/api/Cards')
      .set('Authorization', `Bearer ${token}`)
      .send({ fullName: 'Jim', cardNum: '4111111111111111', expMonth: 12, expYear: 2090 })
    assert.equal(res.status, 201)
    assert.match(String(res.body.data.cardNum), /^\*{12}\d{4}$/, 'API response leaks full PAN')
    const [rows] = await sequelize.query('SELECT cardNum FROM Cards ORDER BY id DESC LIMIT 1')
    assert.match(String((rows as any[])[0].cardNum), /^\*{12}\d{4}$/, 'PAN stored in clear in DB')
  })

  // GDPR Art.17 : erasure request must actually erase / anonymise personal data
  void it('GDPR Art.17: an erasure request removes or anonymises the user record', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app).post('/dataerasure')
      .set('Cookie', `token=${token}`).field('email', 'jim@juice-sh.op')
    assert.ok(res.status < 400, `erasure endpoint returned ${res.status}`)
    const [rows] = await sequelize.query('SELECT email FROM Users WHERE id = 2')
    const stillIdentifiable = (rows as any[]).some(r => r.email === 'jim@juice-sh.op')
    assert.equal(stillIdentifiable, false, 'user e-mail still stored after erasure request')
    const [cards] = await sequelize.query('SELECT id FROM Cards WHERE UserId = 2')
    assert.equal((cards as any[]).length, 0, 'payment cards of erased user still stored')
  })

  // PCI-DSS 6.2.4 (ex 6.5.x) / GDPR Art.32 : no internal error detail to clients
  void it('PCI-DSS 6 / GDPR Art.32: errors do not leak DB internals or stack traces', async () => {
    for (const accept of ['application/json', 'text/html']) {
      const res = await request(app).get('/rest/products/search?q=%27%28').set('Accept', accept)
      assert.equal(res.status, 500)
      assert.doesNotMatch(res.text, /SQLITE_ERROR|SequelizeDatabaseError|node_modules|\bat .+\(.+:\d+:\d+\)/,
        `error body leaks internals for Accept: ${accept}`)
    }
  })
})
