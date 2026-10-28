/*
 * Security-as-Code cho F01 (SQL injection ở đăng nhập) và F02 (SQL injection ở tìm kiếm sản phẩm).
 * Các assertion mô tả hành vi AN TOÀN mong muốn: trên mã còn lỗi chúng phải FAIL (phát hiện),
 * sau khi vá chúng phải PASS (kiểm chứng bản vá) và được giữ lại để chống tái diễn.
 */
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from '../helpers/setup'

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

void describe('F02 — tìm kiếm sản phẩm không bị SQL injection trích xuất dữ liệu', () => {
  const union = "qwert')) UNION SELECT id,email,password,role,1,2,3,4,5 FROM Users--"

  void it('tìm kiếm hợp lệ vẫn trả về sản phẩm (200)', async () => {
    const res = await request(app).get('/rest/products/search').query({ q: 'apple' })
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
  })

  void it('payload UNION SELECT không trích được email người dùng từ bảng Users', async () => {
    const res = await request(app).get('/rest/products/search').query({ q: union })
    assert.equal(res.status, 200)
    const names = (res.body.data ?? []).map((r: any) => String(r.name ?? ''))
    assert.ok(!names.some((n: string) => n.includes('@juice-sh.op')), 'SQL injection: trích được email người dùng')
  })

  void it('payload UNION không làm lộ hash mật khẩu (chuỗi 32 hex) trong kết quả', async () => {
    const res = await request(app).get('/rest/products/search').query({ q: union })
    const blob = JSON.stringify(res.body.data ?? [])
    assert.ok(!/\b[a-f0-9]{32}\b/.test(blob), 'SQL injection: lộ hash mật khẩu trong kết quả tìm kiếm')
  })
})
