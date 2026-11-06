# Quy trình DevSecOps gắn với Git

Mỗi lần sửa lỗi hoặc thay đổi mã nguồn, các cổng kiểm soát trong sơ đồ DevSecOps của báo cáo (`report/screenshots/devsecops-pipeline.png`) chạy tự động theo đúng thứ tự pha:

```
Plan ─► Code ─► Build ─► Test ─► Release ─► Deploy ─► Operate ─► Monitor
```

Toàn bộ logic nằm trong **một script**, `devsecops/pipeline.sh`. Ba nơi gọi nó, nên máy thành viên và CI chạy đúng cùng một bộ cổng:

| Điểm kích hoạt | Khi nào | Chạy những pha nào |
|---|---|---|
| `.githooks/pre-commit` | `git commit` | Code + các cổng tĩnh của Build/Deploy (`--staged --quick`), khoảng 20–60 giây |
| `.githooks/pre-push` | `git push` | Code → Build → Test → Release → Deploy (chỉ kiểm chính sách), trên các commit sắp đẩy |
| `.github/workflows/devsecops.yml` | push lên `main`, `fix/**`, `tv-*`; pull request vào `main` | Cả 7 pha, có triển khai thật trên runner rồi kiểm tra Operate/Monitor |

Hook có thể bị bỏ qua bằng `--no-verify`. Vì vậy cổng bắt buộc cuối cùng là workflow trên GitHub: hãy đặt branch protection cho `main` để yêu cầu job **DevSecOps pipeline** phải đạt.

## Các cổng theo pha

| Pha | Cổng | Kiểm soát | Chặn khi |
|---|---|---|---|
| Code | Gitleaks v8.30.1 | Quét secret | Có secret trong **dòng được thêm** (staging, hoặc các commit `gốc..HEAD`) |
| Code | Semgrep 1.180.0 | SAST, so với bản gốc | Có cảnh báo **mới** trên tệp mã server đã đổi. Cảnh báo có sẵn của Juice Shop gốc không chặn |
| Build | `conftest verify` | Unit test cho luật Rego | 26 ca của `policy/` và `report/policy/` không đạt hết |
| Build | Conftest `docker_security.rego` | Policy as Code (F04) | `Dockerfile` hoặc `deploy/Dockerfile.hotfix` vi phạm (thiếu `USER`, mở cổng 22/3306, secret trong `ENV`, `:latest`…) |
| Build | Phạm vi image hotfix | Cảnh báo (không chặn) | Có thay đổi mã server nằm ngoài 2 route mà `Dockerfile.hotfix` đóng gói |
| Build | `tsc` + `docker build` | Đóng gói | Lỗi biên dịch. Image chỉ được gắn tag **ứng viên** `juice-shop:ci-<sha>` |
| Test | node:test + Supertest | Test-Driven Security (F01, F02) | Một ca trong `test/api/security/` đỏ |
| Release | Trivy 0.76.1 | SCA | Có CVE **CRITICAL mới**, tức không nằm trong `devsecops/.trivyignore` (11 CVE có sẵn của image gốc) |
| Release | Dockle 0.4.15 | CIS image | Có WARN hoặc FATAL |
| Release | Gắn tag phát hành | — | Chỉ khi qua đủ các cổng trên: `ci-<sha>` → `juice-shop:hotfix-f01-f02` (tag mà compose triển khai) |
| Deploy | Conftest `compose.rego` | Policy as Code (F03) | Backend mở cổng host, bind ngoài `127.0.0.1`, `privileged`, mount `docker.sock`, secret inline |
| Deploy | `docker compose up --wait` | Triển khai | Container không lên hoặc không healthy |
| Operate | Conftest `runtime.rego` trên `docker inspect` | Compliance as Code | Container đang chạy là root, thiếu `cap_drop: ALL` hay `no-new-privileges`, không giới hạn CPU/PID, hoặc backend có cổng host |
| Operate | Kiểm tra qua proxy 3102 | Kiểm chứng hành vi | `/` ≠ 200, `/metrics` ≠ 404, thiếu header `nosniff`/`no-referrer`, đăng nhập dồn dập mà không nhận 429 |
| Monitor | Prometheus | Giám sát | Target `juice-shop` không UP, hoặc chưa nạp luật `HighClientErrorRate`. Bỏ qua (SKIP) nếu stack giám sát chưa chạy |

**Lọc theo loại thay đổi:** sửa tài liệu (`report/`…) thì chỉ chạy pha Code. Sửa mã ứng dụng hoặc hạ tầng thì chạy đủ các pha. Thêm `--full` để luôn chạy hết.
**Dừng sớm:** pha nào FAIL thì các pha sau bị SKIP. Riêng `--quick` (pre-commit) chạy hết các cổng tĩnh, để thấy mọi lỗi trong một lần.

## Cài đặt (mỗi thành viên, một lần sau khi clone)

Cần: Git for Windows (Git Bash), Docker Desktop đang chạy, Node.js 22–26.

```bash
npm install                      # postinstall build frontend: test cần khi Juice Shop khởi động
bash devsecops/install-hooks.sh  # git config core.hooksPath .githooks + kiểm tra công cụ
```

Lần đầu chạy sẽ tải các image công cụ (Semgrep, Gitleaks, Conftest, Trivy, Dockle). Cơ sở dữ liệu CVE của Trivy được giữ trong volume `devsecops-trivy-cache`.

## Quy trình sửa lỗi bằng Git

```bash
git switch -c fix/<mô-tả> main   # Plan: mỗi lỗi một nhánh
# ... sửa mã, thêm ca kiểm thử vào test/api/security/ (đỏ trước khi vá, xanh sau khi vá)
git add -p
git commit -m "fix: ..."         # pre-commit: Gitleaks + Semgrep + Conftest
git push -u github fix/<mô-tả>   # pre-push: Code → Build → Test → Release → Deploy (chính sách)
# mở pull request vào main → GitHub Actions chạy đủ 7 pha → đạt thì merge
bash devsecops/pipeline.sh deploy operate monitor   # triển khai bản đã phát hành lên 3102 và kiểm tra
```

Khi đã đạt, pre-push ghi dấu theo SHA (`.devsecops/pass-<sha>`). Nhờ đó đẩy cùng commit lên nhánh thứ hai (ví dụ `main` rồi `fix/f01-f04`) không phải chạy lại.

## Demo

Kịch bản demo từng bước (commit bị chặn, hạ tầng sai bị chặn, chạy đủ 7 pha, CI đỏ khi bỏ qua hook): `devsecops/DEMO.md`. Dọn sau demo: `bash devsecops/demo-cleanup.sh`.

## Chạy tay

```bash
bash devsecops/pipeline.sh                        # cả 7 pha, so cây làm việc với v20.2.0
bash devsecops/pipeline.sh code build test        # chỉ vài pha
bash devsecops/pipeline.sh --base origin/main     # chỉ xét thay đổi so với một nhánh
bash devsecops/pipeline.sh --help
```

Từ PowerShell thì gọi qua bash của Git: `& "C:\Program Files\Git\bin\bash.exe" devsecops/pipeline.sh`.

Log của từng cổng nằm trong `.devsecops/NN-<Pha>.log` (đã gitignore). Bảng tổng kết nằm ở `.devsecops/summary.md`.

**Mã thoát:** `0` nghĩa là không có FAIL (WARN không chặn), `1` nghĩa là có cổng FAIL.

## Giới hạn

- `deploy/Dockerfile.hotfix` chỉ chép `routes/login.js` và `routes/fileServer.js` lên image gốc. Thay đổi mã server ở chỗ khác vẫn qua được Code/Test, nhưng **không** có trong image. Cổng "Phạm vi image hotfix" sẽ cảnh báo, và muốn đưa thay đổi đó lên thì phải sửa Dockerfile.
- `devsecops/.trivyignore` là danh sách rủi ro đã chấp nhận. Khi cơ sở dữ liệu CVE có thêm CVE CRITICAL cho thư viện cũ của image gốc, cổng Trivy sẽ đỏ dù mã không đổi. Khi đó cần đánh giá CVE đó rồi thêm vào danh sách hoặc nâng cấp gói.
- Pha Operate gửi tới 12 yêu cầu đăng nhập để kiểm tra rate-limit, nên trong khoảng 1 phút sau đó đăng nhập qua 3102 có thể nhận 429.
