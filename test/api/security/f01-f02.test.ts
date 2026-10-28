/*
 * Security-as-Code cho F01 (SQL injection ở đăng nhập) và F02 (path traversal qua poison null byte ở route tải tệp).
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

void describe('F02 — tải tệp tĩnh không bị path traversal qua poison null byte', () => {
  void it('tệp .md hợp lệ vẫn tải được (200)', async () => {
    const res = await request(app).get('/ftp/legal.md')
    assert.equal(res.status, 200)
  })

  void it('poison null byte không vượt allowlist để đọc package.json.bak (403)', async () => {
    const res = await request(app).get('/ftp/package.json.bak%2500.md')
    assert.equal(res.status, 403, 'path traversal: đọc được tệp đuôi bị cấm')
    assert.ok(!res.text.includes('intentionally insecure'), 'lộ nội dung package.json.bak')
  })

  void it('poison null byte không đọc được bản sao lưu coupon (403)', async () => {
    const res = await request(app).get('/ftp/coupons_2013.md.bak%2500.md')
    assert.equal(res.status, 403)
  })
})
