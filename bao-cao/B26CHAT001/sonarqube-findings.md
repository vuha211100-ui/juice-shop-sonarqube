# Kết quả rà quét SonarQube — B26CHAT001 (Đỗ Đức Quốc Anh)

Project SonarQube: `juice-shop-github` — quét nhánh `main` (OWASP Juice Shop v20.2.0, commit `5658473cf`).
SonarQube Community Build 26.10.0.133078, SonarScanner CLI 8.1.0.6389, bộ luật Sonar way.

| # | Loại | Rule | Mức độ | Vị trí |
|---|---|---|---|---|
| 1 | Security | `typescript:S1523` | Critical (Security: High) | routes/b2bOrder.ts:23, routes/userProfile.ts:65, routes/captcha.ts:22, routes/fileUpload.ts:109, lib/xml.ts:38 (5 vị trí) |
| 2 | Security | `typescript:S5332` | Minor (Security: Low) | lib/insecurity.ts:127, 128, 130 (3 URL http trong allowlist redirect); data/datacreator.ts:86, 173 |
| 3 | Code quality | `typescript:S6861` | Critical (Maintainability: High, Reliability: Medium) | models/index.ts:30 (let sequelize), data/datacache.ts:33 (let retrieveBlueprintChallengeFile) |
| 4 | Code quality | `typescript:S6671` | Major (Reliability: Medium) | lib/startup/validatePreconditions.ts:182 (trong hàm checkIfPortIsAvailable) |

## 1. Thực thi code động (eval/vm.runInContext) có thể nhận dữ liệu người dùng

- Rule: typescript:S1523 — Dynamic code execution should not use user-controlled data
- Vị trí: routes/b2bOrder.ts:23, routes/userProfile.ts:65, routes/captcha.ts:22, routes/fileUpload.ts:109, lib/xml.ts:38 (5 vị trí)
- Hướng khắc phục: Không dùng `eval`/`vm.runInContext` với dữ liệu có thể chứa đầu vào của người dùng; xử lý dữ liệu dưới dạng dữ liệu: `JSON.parse` rồi kiểm tra theo schema (ví dụ zod). Nếu thật sự cần thực thi biểu thức thì dùng bộ phân tích biểu thức có danh sách trắng phép toán, chạy trong tiến trình riêng có giới hạn tài nguyên.

```ts
const orderLines = JSON.parse(String(body.orderLinesData))   // chỉ phân tích, không thực thi
const parsed = OrderLinesSchema.parse(orderLines)              // kiểm tra cấu trúc
```

## 2. Giao thức clear-text (URL http) trong mã và cấu hình

- Rule: typescript:S5332 — Clear-text protocols should not be used
- Vị trí: lib/insecurity.ts:127, 128, 130 (3 URL http trong allowlist redirect); data/datacreator.ts:86, 173
- Hướng khắc phục: Đổi mọi URL trong allowlist và dữ liệu mô tả sang `https://`; nếu trang bên thứ ba không hỗ trợ https thì thay bằng tài nguyên khác. Bật HSTS cho ứng dụng để trình duyệt luôn dùng HTTPS.

```ts
  'https://shop.spreadshirt.com/juiceshop',
  'https://shop.spreadshirt.de/juiceshop',
  'https://leanpub.com/juice-shop'
```

## 3. Biến let được export ra ngoài module

- Rule: typescript:S6861 — Mutable variables should not be exported
- Vị trí: models/index.ts:30 (let sequelize), data/datacache.ts:33 (let retrieveBlueprintChallengeFile)
- Hướng khắc phục: Đổi `export let` thành `export const` với giá trị không cần thay đổi (ví dụ kết nối Sequelize); nếu cần cập nhật lúc chạy thì giữ biến ở phạm vi module và chỉ export hàm getter/setter.

```ts
let blueprintFile: string | null = null
export const getRetrieveBlueprintChallengeFile = () => blueprintFile
export function setRetrieveBlueprintChallengeFile (arg: string) { blueprintFile = arg }
```

## 4. Promise bị reject bằng literal thay vì Error

- Rule: typescript:S6671 — Literals should not be used for promise rejection
- Vị trí: lib/startup/validatePreconditions.ts:182 (trong hàm checkIfPortIsAvailable)
- Hướng khắc phục: Chuẩn hoá giá trị reject thành `Error`.

```ts
if (error) {
  reject(error instanceof Error ? error : new Error(String(error)))
}
```
