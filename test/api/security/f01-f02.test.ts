/*
 * Security-as-Code cho F01 (SQL injection ở đăng nhập) và F02 (IDOR khi đọc giỏ hàng).
 * Các assertion mô tả hành vi AN TOÀN mong muốn: trên mã còn lỗi chúng phải FAIL (phát hiện),
 * sau khi vá chúng phải PASS (kiểm chứng bản vá) và được giữ lại để chống tái diễn.
 */
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from '../helpers/setup'
import { login } from '../helpers/auth'

let app: Express

before(async () => {
  ({ app } = await createTestApp())
}, { timeout: 90000 })

const post = async (email: unknown, password: unknown) =>
  await request(app).post('/rest/user/login').set('content-type', 'application/json').send({ email, password })

void describe('F01 — đăng nhập không bị SQL injection', () => {
  void it('đăng nhập đúng email và mật khẩu vẫn trả token', async () => {
    const res = await post('jim@juice-sh.op', 'ncc-1701')
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  for (const payload of ["' OR 1=1--", "admin@juice-sh.op'--", "' UNION SELECT * FROM Users--", "';"]) {
    void it(`payload ${JSON.stringify(payload)} với mật khẩu sai bị từ chối (401)`, async () => {
      const res = await post(payload, 'wrong-password')
      assert.equal(res.status, 401, 'chuỗi nhập vào đã thay đổi câu SQL')
      assert.equal(res.body?.authentication, undefined, 'không được cấp token')
    })
  }

  void it('email không phải chuỗi bị từ chối (401)', async () => {
    const res = await post({ $ne: '' }, 'x')
    assert.equal(res.status, 401)
  })
})

void describe('F02 — chỉ đọc được giỏ hàng của chính mình', () => {
  void it('người dùng đọc giỏ của mình (200)', async () => {
    const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app).get(`/rest/basket/${jim.bid}`).set('Authorization', `Bearer ${jim.token}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.id, jim.bid)
  })

  void it('đọc giỏ của người khác bị từ chối (404, không lộ dữ liệu)', async () => {
    const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
    const res = await request(app).get(`/rest/basket/${bender.bid}`).set('Authorization', `Bearer ${jim.token}`)
    assert.equal(res.status, 404, 'IDOR: trả về giỏ của người khác')
    assert.equal(res.body?.data?.UserId, undefined)
  })

  void it('mã giỏ không hợp lệ bị từ chối (400)', async () => {
    const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app).get('/rest/basket/abc').set('Authorization', `Bearer ${jim.token}`)
    assert.equal(res.status, 400)
  })

  void it('JWT giả mạo (alg none) không đọc được giỏ (401)', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { email: 'jim@juice-sh.op' }, iat: 1508639612, exp: 9999999999 })).toString('base64url')
    const res = await request(app).get('/rest/basket/1').set('Authorization', `Bearer ${header}.${payload}.`)
    assert.equal(res.status, 401)
  })
})
