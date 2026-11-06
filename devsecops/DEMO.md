# Test / demo tích hợp DevSecOps với Git — từng bước (PowerShell)

Kiểm chứng **quy trình DevSecOps gắn với Git** (xem `devsecops/README.md`): khi sửa lỗi hoặc thay đổi mã nguồn, các cổng theo sơ đồ **Code → Build → Test → Release → Deploy → Operate → Monitor** tự chạy lúc `git commit`, `git push` và trên GitHub Actions.

**Thời lượng:** ~10 phút. **Cam kết:** không phần nào đưa bản lỗi vào `main`; xong chạy script dọn (mục 5) là repo và file đã vá trở về nguyên trạng — lý do ở mục 6, cách tự kiểm ở mục 7.

> **Đọc trước khi gõ lệnh (Windows PowerShell 5.1):**
> - **Gõ từng dòng một.** PowerShell 5.1 không có `&&` (báo `The token '&&' is not a valid statement separator`).
> - **Không dùng `git show … > tệp`.** PowerShell ghi tệp thành **UTF-16**, làm hỏng mã nguồn. Dùng `git restore --source …` như bên dưới.
> - **Không gõ `bash …`.** Trong PowerShell, `bash` là bash của **WSL**, không phải Git Bash. Luôn gọi qua biến `$GB` (mục 0).
> - Mọi lệnh chạy tại gốc repo `E:\banhoaqua\juice-shop`.

---

## 0. Chuẩn bị (trước giờ trình bày ~5 phút)

```powershell
Set-Location E:\banhoaqua\juice-shop
[Console]::OutputEncoding = [Text.Encoding]::UTF8      # hiện đúng tiếng Việt trong kết quả các cổng
$GB = "C:\Program Files\Git\bin\bash.exe"               # Git Bash — dùng cho pipeline.sh / demo-cleanup.sh

docker info --format "Docker {{.ServerVersion}} OK"     # Docker Desktop phải chạy (hook gọi công cụ qua Docker)
docker compose up -d                                     # ứng dụng sau vá: http://127.0.0.1:3102
docker compose -f docker-compose.monitoring.yml up -d    # Prometheus :9090, Grafana :3103

git switch main
git status -s routes deploy docker-compose.yml           # phải KHÔNG in gì (file đã vá còn nguyên)
git config core.hooksPath                                # phải in: .githooks   (chưa có -> & $GB devsecops/install-hooks.sh)
```

Mở sẵn trên trình duyệt: slide sơ đồ DevSecOps, và tab **Actions** `https://github.com/vuha211100-ui/juice-shop-sonarqube/actions` (lần chạy xanh đủ 7 pha: `…/actions/runs/42230498979`).

> Biến `$GB` chỉ tồn tại trong cửa sổ PowerShell hiện tại — mở cửa sổ mới thì gõ lại 2 dòng `[Console]…` và `$GB = …`.

---

## Phần 1 — Commit lỗi bị chặn ngay trên máy (F01 tái diễn + lộ khóa) · ~1 phút

**Ý nói:** "Một bạn vô tình đưa lại `login.ts` còn lỗi SQL injection và dán khóa AWS vào mã. Cổng chặn ngay lúc commit — mã chưa vào kho."

```powershell
git restore --source 5658473cf -- routes/login.ts                         # lấy login.ts gốc CHƯA vá (F01) ra đĩa
Add-Content routes/login.ts 'export const awsKey = "AKIAZ7Q4M2K9LX3VBN8P"'  # khóa giả
git add routes/login.ts
git commit -m "demo"                                                       # hook pre-commit chạy (~20 s)
```

**Kết quả mong đợi** — commit bị hủy:
```
  Code     Gitleaks — quét secret                          FAIL
           │ WRN leaks found: 1   …   RuleID: generic-api-key
  Code     Semgrep — SAST, chặn cảnh báo mới               FAIL
           │ NEW  routes/login.ts:34  [express-sequelize-injection] …
✗ Pipeline FAIL — sửa lỗi ở cổng FAIL rồi chạy lại.
```

**Chỉ ra:** Semgrep chỉ chặn cảnh báo **MỚI** so với bản đã commit — Juice Shop vốn có nhiều lỗ hổng cố ý; chặn mọi cảnh báo thì không commit được gì.

```powershell
git restore --staged --worktree routes/login.ts                            # trả lại bản ĐÃ VÁ
```

---

## Phần 2 — Thay đổi hạ tầng sai bị chặn (F03 + F04) · ~1 phút

**Ý nói:** "Lần này sai ở hạ tầng: mở cổng backend ra host (F03) và bỏ dòng chạy non-root trong Dockerfile (F04). Policy as Code chặn và báo **mọi** lỗi trong một lần."

```powershell
$p = (Resolve-Path docker-compose.yml).Path;      [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace 'labels: \{lab\.exposure: internal\}.*', 'ports: ["0.0.0.0:3000:3000"]'))
$p = (Resolve-Path deploy\Dockerfile.hotfix).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace '(?m)^USER 65532\r?$', ''))
git add docker-compose.yml deploy/Dockerfile.hotfix
git commit -m "demo"
```
*(Hai dòng `$p = …` sửa tệp bằng .NET để giữ UTF-8 không BOM — `Set-Content` của PowerShell 5.1 sẽ thêm BOM.)*

**Kết quả mong đợi** — commit bị hủy:
```
  Build    Conftest — Dockerfile (docker_security.rego)    FAIL
           │ FAIL - deploy/Dockerfile.hotfix - … LEAST-PRIVILEGE: final stage has no explicit USER …
  Deploy   Conftest — docker-compose.yml (compose.rego)    FAIL
           │ FAIL - … [F03 NET-02] service 'juice-shop' publishes ports but is not an edge service …
           │ FAIL - … [GDPR Art.32 NET-01] service 'juice-shop' publishes 0.0.0.0:3000:3000 …
```

```powershell
git restore --staged --worktree docker-compose.yml deploy/Dockerfile.hotfix
```

---

## Phần 3 — Mã đã vá chạy qua đủ 7 pha · ~2 phút

**Ý nói:** "Đây là toàn bộ pipeline, đúng thứ tự trên sơ đồ — giống hệt cái chạy khi `git push` và trên GitHub."

```powershell
& $GB devsecops/pipeline.sh
```

| Pha | Cổng | Điểm cần nói |
|---|---|---|
| Code | Gitleaks, Semgrep | Chỉ chặn phát hiện **mới** so với bản gốc v20.2.0 |
| Build | `conftest verify` (26 ca), Conftest Dockerfile, `tsc`, `docker build` | Image chỉ mang tag **ứng viên** `juice-shop:ci-<sha>` |
| Test | node:test + Supertest | 11 ca F01/F02 xanh |
| Release | Trivy, Dockle, gắn tag | Đạt cả hai mới gắn tag triển khai `hotfix-f01-f02` |
| Deploy | Conftest compose, `docker compose up` | Triển khai lên 3102 |
| Operate | `runtime.rego`, `/`→200, `/metrics`→404, header, 429 | Compliance as Code trên container đang chạy |
| Monitor | Prometheus | Target UP + luật `HighClientErrorRate` |

**Kết quả mong đợi:** `20 PASS · 1 WARN · 0 FAIL` và `✓ Pipeline đạt.` **WARN là trung thực:** 5 tệp đã sửa ngoài 2 route không được đóng gói vào image hotfix (Dockerfile.hotfix chỉ chép `login.js`, `fileServer.js`).

> ⚠ Pha Operate bắn tới 12 lần đăng nhập vào 3102 để kiểm rate-limit → **~1 phút sau đó đăng nhập qua 3102 trả 429**. Demo SQLi (tv1) qua 3102 thì làm **trước** phần này hoặc chờ 1 phút.

---

## Phần 4 — GitHub Actions: cổng không bỏ qua được · ~2 phút

**4.1 Lần chạy xanh.** Mở `…/actions/runs/42230498979`: mỗi pha là một step, log các cổng tải về ở mục *Artifacts*.

**Ý nói:** "Hook trên máy bỏ qua được bằng `--no-verify`. GitHub Actions thì không — đây là cổng bắt buộc trước khi merge vào `main`."

**4.2 Cố tình bỏ qua hook → CI vẫn bắt.** Chạy trước giờ trình bày ~5 phút (một lần chạy trên GitHub mất ~4 phút), lúc trình bày chỉ mở kết quả:

```powershell
git switch -c fix/demo-ci main                              # nhánh riêng — main không bị đụng tới
git restore --source 5658473cf -- routes/login.ts           # F01 tái diễn
git add routes/login.ts                                     # CHỈ add tệp này (không dùng commit -a: sẽ dính tệp khác đang sửa)
git commit -m "demo: bypass hook" --no-verify               # bỏ qua pre-commit
git push github fix/demo-ci --no-verify                     # bỏ qua pre-push
git switch main                                             # về main -> login.ts trên đĩa tự về bản đã vá
```

Trên tab Actions, lần chạy của nhánh `fix/demo-ci` **đỏ ở step "Code · Gitleaks + Semgrep"** với `NEW routes/login.ts:34 [express-sequelize-injection]`.

**Câu hỏi hay gặp:**
- *"Có tự triển khai lên môi trường thật không?"* — Không. Deploy trên Actions là lên **máy ảo tạm** để chạy Operate/Monitor kiểm chứng, xong thì hủy. Cập nhật 3102 là lệnh tay `& $GB devsecops/pipeline.sh deploy operate monitor` (chưa có CD).
- *"Sao cần cả hook lẫn CI?"* — Hook cho phản hồi sớm trên máy từng người (shift-left); CI là cổng không bỏ qua được.
- *"CVE CRITICAL trong image thì sao?"* — 11 CVE có sẵn của image gốc ghi là rủi ro đã chấp nhận trong `devsecops/.trivyignore`; cổng chặn CVE CRITICAL **mới**.

---

## 5. Dọn sau test

```powershell
& $GB devsecops/demo-cleanup.sh          # hỏi xác nhận trước khi trả tệp;  thêm -y để không hỏi
```

Script:
1. Trả `routes/login.ts`, `docker-compose.yml`, `deploy/Dockerfile.hotfix` về **bản đã commit (bản đã vá)** — hỏi trước.
2. Về `main`; xóa nhánh `fix/demo-ci` ở local và trên GitHub; hủy + xóa các lần chạy Actions của nhánh đó.
3. Gỡ tag image ứng viên `juice-shop:ci-*` (tag đang được container dùng thì giữ, có báo); xóa log `.devsecops/`.
4. Kiểm tra lại: tệp demo sạch, đang ở `main` và khớp remote, hook còn bật, image `hotfix-f01-f02` còn, stack 3102 trả 200.

Kết thúc bằng `✓ Đã dọn xong.` Các thay đổi chưa commit **khác** (ví dụ trong `report/`) được giữ nguyên.

Dừng hẳn môi trường khi không demo nữa: `docker compose -f docker-compose.monitoring.yml down` rồi `docker compose down`.

---

## 6. Vì sao test không ảnh hưởng file đã vá

| Lo ngại | Thực tế |
|---|---|
| Bản lỗi lọt vào `main` | Không thể: Phần 1–2 commit **bị chặn**, bản lỗi chỉ nằm tạm trên đĩa; `git restore` lấy lại bản đã vá từ commit hiện tại |
| Phần 4 có commit thật | Commit nằm trên **nhánh riêng** `fix/demo-ci`; `main` không đổi; script dọn xóa nhánh cả local lẫn GitHub |
| Image / container 3102 bị thay bằng bản lỗi | Phần 1–2 không build gì; Phần 3 build từ mã đã vá; Phần 4 chỉ chạy trên máy ảo GitHub. Kể cả khi chạy pipeline lúc mã còn lỗi, pha Test FAIL nên image **không** được gắn tag `hotfix-f01-f02` mà compose triển khai |
| Quên hoàn tác | `demo-cleanup.sh` trả 3 tệp demo về bản đã commit, về `main`, rồi tự kiểm tra |

**Lưu ý duy nhất:** script trả `login.ts`, `docker-compose.yml`, `Dockerfile.hotfix` về bản đã commit — nếu bạn đang có chỉnh sửa **thật** chưa commit trong 3 tệp này thì sẽ mất. Vì vậy script hỏi trước; chỉ dùng `-y` khi chắc chắn.

---

## 7. Tự kiểm: `routes/login.ts` đang là bản đã vá?

```powershell
git status -s routes deploy docker-compose.yml          # không in gì = giống hệt bản đã commit (đã vá)
Select-String -Path routes\login.ts -Pattern 'bind: \{ email'   # có dòng này = bản ĐÃ VÁ (tham số bind)
Select-String -Path routes\login.ts -Pattern 'email = ''\$\{'   # có dòng này = bản CŨ (ghép chuỗi) — phải KHÔNG in gì
node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit test/api/security/f01-f02.test.ts   # cuối: pass 11, fail 0
git log --oneline -1                                     # main không có commit lạ
git rev-parse --short github/main                        # khớp dòng trên
```

| | Bản đã vá (đúng) | Bản cũ (lỗi F01) |
|---|---|---|
| Truy vấn | `…WHERE email = $email AND password = $password…` + `bind: { email, password: … }` | `` `…WHERE email = '${req.body.email || ''}'…` `` (ghép chuỗi) |
| Test `f01-f02` | 11/11 pass | 5 ca SQLi fail (200 thay vì 401) |

Nếu thấy bản cũ hoặc tệp bị hỏng (ví dụ đã lỡ chạy `git show … > tệp` trong PowerShell):
```powershell
& $GB devsecops/demo-cleanup.sh          # hoặc chỉ riêng tệp:  git restore --staged --worktree routes/login.ts
```

---

## Gỡ rối

| Hiện tượng | Cách xử lý |
|---|---|
| `The token '&&' is not a valid statement separator` | PowerShell 5.1 không có `&&` — gõ từng lệnh một dòng |
| `login.ts` thành "UTF-16" / test lỗi lạ sau khi chạy `git show … >` | Do PowerShell ghi UTF-16 — chạy script dọn hoặc `git restore --staged --worktree routes/login.ts` |
| `bash devsecops/...` báo không thấy tệp / chạy trong Linux | Đó là bash của WSL — dùng `& $GB devsecops/...` |
| `git commit` treo / báo lỗi Docker | Docker Desktop chưa chạy — bật lên rồi commit lại |
| Commit không chạy cổng nào | Hook chưa bật: `& $GB devsecops/install-hooks.sh` |
| Lần đầu chạy rất lâu | Đang tải image công cụ (Semgrep, Trivy…) — chạy Phần 3 một lần lúc chuẩn bị |
| Đăng nhập 3102 trả 429 | Do pha Operate kiểm rate-limit — chờ 1 phút |
| Phần 4 không thấy lần chạy | Actions chưa bật trên fork, hoặc tên nhánh không khớp `fix/**` |

*(Dùng Git Bash thay PowerShell: các lệnh `git` giữ nguyên; `& $GB devsecops/x.sh` thành `bash devsecops/x.sh`; Phần 2 dùng `sed -i 's/^    labels: {lab.exposure: internal}.*/    ports: ["0.0.0.0:3000:3000"]/' docker-compose.yml` và `sed -i 's/^USER 65532$//' deploy/Dockerfile.hotfix`.)*
