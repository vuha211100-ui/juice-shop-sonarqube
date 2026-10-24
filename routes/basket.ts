/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // F02: danh tính lấy từ phiên do máy chủ cấp khi đăng nhập (authenticatedUsers), không tin dữ liệu client gửi lên.
      // JWT giả mạo chưa từng được cấp qua /rest/user/login thì không có UserId hợp lệ.
      const user = security.authenticatedUsers.from(req)
      if (!user?.data?.id) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
        return
      }
      const id = Number(req.params.id)
      if (!Number.isSafeInteger(id) || id <= 0) {
        res.status(400).json({ status: 'error', message: 'Invalid basket id' })
        return
      }
      // Ràng buộc chủ sở hữu ngay trong truy vấn: giỏ của người khác cho kết quả rỗng giống giỏ không tồn tại.
      // Semgrep node_nosqli_injection là dương tính giả ở đây: id đã ép số nguyên, UserId lấy từ phiên máy chủ, Sequelize/SQLite không phải NoSQL.
      const basket = await BasketModel.findOne({ where: { id, UserId: user.data.id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] }) // nosemgrep: rules.ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection
      if (basket === null) {
        res.status(404).json({ status: 'error', message: 'Basket not found' })
        return
      }
      if ((basket.Products != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
