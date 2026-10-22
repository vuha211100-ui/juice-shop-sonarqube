# Kết quả rà quét SonarQube — B26CHAT042

Project SonarQube: `juice-shop-github` — quét nhánh `main` (OWASP Juice Shop v20.2.0, commit `5658473cf`).
SonarQube Community Build 26.10.0.133078, SonarScanner CLI 8.1.0.6389, bộ luật Sonar way.

| # | Loại | Rule | Mức độ | Vị trí |
|---|---|---|---|---|
| 1 | Security | `typescript:S4507` | Minor (Security: Low) | server.ts:701 |
| 2 | Security | `typescript:S5693` | Major (Security: Medium) | server.ts:719 (cấu hình multer uploadToDisk cho POST /rest/memories) |
| 3 | Code quality | `typescript:S7737` | Minor (Reliability: Medium, Maintainability: Medium) | frontend/src/hacking-instructor/helpers/helpers.ts:34 (4 vị trí cùng rule) |
| 4 | Code quality | `typescript:S7773` | Minor (Reliability: Medium, Maintainability: Low) | frontend/src/app/Services/basket.service.ts:65 (19 vị trí cùng rule) |

## 1. Middleware debug errorhandler() bật trong môi trường production

- Rule: typescript:S4507 — Debugging features should not be enabled in production
- Vị trí: server.ts:701
- Hướng khắc phục: Chỉ bật `errorhandler()` khi phát triển; ở production dùng handler riêng ghi chi tiết vào log server và trả cho client thông báo chung kèm mã sự kiện. Bản vá này đã áp dụng trên nhánh `lab-security-as-code` của repo.

```ts
if (process.env.NODE_ENV === 'development') app.use(errorhandler())
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  const eventId = utils.randomHexString(12)
  logger.error(`[${eventId}] ${err?.stack ?? err}`)
  res.status(err?.status ?? 500).json({ status: 'error', message: 'An internal error occurred', eventId })
})
```

## 2. Upload file không giới hạn kích thước

- Rule: typescript:S5693 — HTTP request content length should be limited
- Vị trí: server.ts:719 (cấu hình multer uploadToDisk cho POST /rest/memories)
- Hướng khắc phục: Đặt giới hạn kích thước và số lượng file phù hợp nghiệp vụ; giới hạn thêm ở reverse proxy (`client_max_body_size` của nginx).

```ts
const uploadToDisk = multer({
  storage: multer.diskStorage({ /* ... */ }),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 }   // tối đa 2 MB, 1 file
})
```

## 3. Dùng object literal làm giá trị mặc định cho tham số

- Rule: typescript:S7737 — Objects should not be used as default parameters
- Vị trí: frontend/src/hacking-instructor/helpers/helpers.ts:34 (4 vị trí cùng rule)
- Hướng khắc phục: Dùng destructuring với giá trị mặc định cho từng thuộc tính, kèm kiểu rõ ràng.

```ts
export function waitForInputToHaveValue (inputSelector: string, value: string,
  { ignoreCase = true, replacement = [] }: { ignoreCase?: boolean, replacement?: string[][] } = {}) {
```

## 4. Dùng parseInt toàn cục thay vì Number.parseInt

- Rule: typescript:S7773 — Number static methods and properties should be preferred over global equivalents
- Vị trí: frontend/src/app/Services/basket.service.ts:65 (19 vị trí cùng rule)
- Hướng khắc phục: Dùng `Number.parseInt` và kiểm tra giá trị trước khi gọi API.

```ts
const bid = Number.parseInt(sessionStorage.getItem('bid') ?? '', 10)
if (!Number.isNaN(bid)) {
  this.find(bid).subscribe({ /* ... */ })
}
```
