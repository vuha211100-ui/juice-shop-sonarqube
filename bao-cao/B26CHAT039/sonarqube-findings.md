# Kết quả rà quét SonarQube — B26CHAT039

Project SonarQube: `juice-shop-github` — quét nhánh `main` (OWASP Juice Shop v20.2.0, commit `5658473cf`).
SonarQube Community Build 26.10.0.133078, SonarScanner CLI 8.1.0.6389, bộ luật Sonar way.

| # | Loại | Rule | Mức độ | Vị trí |
|---|---|---|---|---|
| 1 | Security | `typescript:S6437` | Blocker (Security: Blocker) | lib/insecurity.ts:42 (hàm hmac, dùng cho câu trả lời bảo mật tại models/securityAnswer.ts:45) |
| 2 | Security | `typescript:S6268` | Blocker (Security: Blocker) | frontend/src/app/search-result/search-result.component.ts:111 (9 vị trí cùng rule trong frontend) |
| 3 | Code quality | `Web:InputWithoutLabelCheck` | Major (Reliability: Medium) | frontend/src/app/accounting/accounting.component.html:86 (9 vị trí cùng rule) |
| 4 | Code quality | `typescript:S8786` | Major (Reliability: Medium) | frontend/src/app/change-password/change-password.component.ts:81 (10 vị trí cùng rule) |

## 1. Khoá HMAC viết cứng trong mã nguồn

- Rule: typescript:S6437 — Credentials should not be hard-coded
- Vị trí: lib/insecurity.ts:42 (hàm hmac, dùng cho câu trả lời bảo mật tại models/securityAnswer.ts:45)
- Hướng khắc phục: Đưa khoá ra biến môi trường/secret manager, đổi khoá và yêu cầu người dùng đặt lại câu trả lời bảo mật.

```ts
const HMAC_KEY = process.env.HMAC_KEY
if (!HMAC_KEY) throw new Error('HMAC_KEY is not configured')
export const hmac = (data: string) => crypto.createHmac('sha256', HMAC_KEY).update(data).digest('hex')
```

## 2. Tắt cơ chế sanitize của Angular khi hiển thị mô tả sản phẩm

- Rule: typescript:S6268 — Angular built-in sanitization should not be disabled
- Vị trí: frontend/src/app/search-result/search-result.component.ts:111 (9 vị trí cùng rule trong frontend)
- Hướng khắc phục: Bỏ `bypassSecurityTrust*`, để Angular tự lọc khi gán vào `[innerHTML]`; nếu cần cho phép một số thẻ định dạng thì lọc bằng thư viện như DOMPurify trước khi hiển thị.

```ts
// Bỏ bypass: Angular tự sanitize khi gán vào [innerHTML]
// <div [innerHTML]="product.description"></div>
const safe = this.sanitizer.sanitize(SecurityContext.HTML, description)
```

## 3. Ô nhập liệu không có nhãn (khả năng truy cập)

- Rule: Web:InputWithoutLabelCheck — "input", "select" and "textarea" tags should be labeled
- Vị trí: frontend/src/app/accounting/accounting.component.html:86 (9 vị trí cùng rule)
- Hướng khắc phục: Thêm `<mat-label>` hoặc `aria-label` mô tả ô nhập.

```ts
<mat-form-field class="input-field">
  <mat-label>{{ 'LABEL_PRICE' | translate }}</mat-label>
  <input #price matInput type="number" value="{{ element.price }}"
         [attr.aria-label]="'Giá của ' + element.name">
```

## 4. Biểu thức chính quy có thời gian chạy siêu tuyến tính

- Rule: typescript:S8786 — Regular expressions should not cause non-linear backtracking
- Vị trí: frontend/src/app/change-password/change-password.component.ts:81 (10 vị trí cùng rule)
- Hướng khắc phục: Neo regex và tách thành các phép kiểm tra đơn giản, mỗi phép chạy tuyến tính.

```ts
const pw: string = this.newPasswordControl.value
const ok = pw.length >= 12 && pw.length <= 30 && /^[A-Za-z\d@$!%*?&]+$/.test(pw) &&
  /[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[@$!%*?&]/.test(pw)
```
