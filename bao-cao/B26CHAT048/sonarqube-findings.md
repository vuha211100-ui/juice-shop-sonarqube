# Kết quả rà quét SonarQube — B26CHAT048

Project SonarQube: `juice-shop-github` — quét nhánh `main` (OWASP Juice Shop v20.2.0, commit `5658473cf`).
SonarQube Community Build 26.10.0.133078, SonarScanner CLI 8.1.0.6389, bộ luật Sonar way.

| # | Loại | Rule | Mức độ | Vị trí |
|---|---|---|---|---|
| 1 | Security | `typescript:S4790` | Critical (Security: High) | lib/insecurity.ts:41 (hàm hash, dùng cho mật khẩu tại models/user.ts:73 và routes/2fa.ts:107) |
| 2 | Security | `secrets:S6706` | Blocker (Security: Blocker) | lib/insecurity.ts:21 (hằng privateKey) |
| 3 | Code quality | `typescript:S9383` | Major (Reliability: Medium) | frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.ts:74 (34 vị trí cùng rule trong dự án) |
| 4 | Code quality | `typescript:S6638` | Major (Reliability: Medium) | lib/challengeUtils.ts:59 |

## 1. Băm mật khẩu bằng thuật toán yếu MD5

- Rule: typescript:S4790 — Weak hashing algorithms should not be used
- Vị trí: lib/insecurity.ts:41 (hàm hash, dùng cho mật khẩu tại models/user.ts:73 và routes/2fa.ts:107)
- Hướng khắc phục: Dùng thuật toán băm mật khẩu chuyên dụng có salt và hệ số chi phí (bcrypt, scrypt, Argon2id); băm lại mật khẩu cũ theo thuật toán mới ở lần đăng nhập kế tiếp.

```ts
import bcrypt from 'bcrypt'
export const hashPassword = async (pw: string) => await bcrypt.hash(pw, 12)
export const verifyPassword = async (pw: string, stored: string) => await bcrypt.compare(pw, stored)
```

## 2. Private key RSA dùng ký JWT nằm thẳng trong mã nguồn

- Rule: secrets:S6706 — Cryptographic private keys should not be disclosed
- Vị trí: lib/insecurity.ts:21 (hằng privateKey)
- Hướng khắc phục: Thu hồi và tạo khoá mới; đọc khoá từ biến môi trường hoặc secret manager (Docker/Kubernetes secret, Vault); xoá khoá khỏi lịch sử git (`git filter-repo`) và bật quét secret ở pre-commit/CI.

```ts
const privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE ?? '/run/secrets/jwt_private_key', 'utf8')
```

## 3. Promise không được xử lý lỗi khi nạp module động

- Rule: typescript:S9383 — Promises should not be left unhandled
- Vị trí: frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.ts:74 (34 vị trí cùng rule trong dự án)
- Hướng khắc phục: Thêm `.catch()` xử lý lỗi; nếu cố ý bỏ qua kết quả thì viết rõ bằng `void`.

```ts
import('../../confetti')
  .then(module => { module.shootConfetti() })
  .catch(err => { console.error('Không tải được hiệu ứng confetti', err) })
```

## 4. Toán tử ?? với vế trái không bao giờ null (code chết)

- Rule: typescript:S6638 — Binary expressions should not always return the same value
- Vị trí: lib/challengeUtils.ts:59
- Hướng khắc phục: Bỏ phần `?? false` thừa, hoặc dùng `fullChallenge.hasCodingChallenge ?? false` nếu muốn giữ kiểu gốc.

```ts
hasCodingChallenge = Boolean(fullChallenge.hasCodingChallenge)
```
