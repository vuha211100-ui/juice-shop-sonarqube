# Báo cáo DevSecOps — OWASP Juice Shop (nhóm)

Học phần **DevOps và DevSecOps (SEC4349)** — Học viện Công nghệ Bưu chính Viễn thông, Khoa An toàn thông tin.
Đánh giá an toàn / bảo vệ dữ liệu người dùng trên **OWASP Juice Shop v20.2.0**, xử lý 4 lỗi theo mạch *trước → sau*.

Toàn bộ mã vá nằm ở **gốc repo** (nhánh `fix/f01-f04`); thư mục `report/` này chứa báo cáo + demo.

## Bắt đầu nhanh

1. `git checkout fix/f01-f04`
2. Mở **`report/DEMO.md`** — hướng dẫn khởi động môi trường và chạy cả 4 demo.
3. Đọc **`report/BaoCao_DevSecOps_JuiceShop_gon.pdf`** (nguồn: `report/report_concise.md`).
4. Thuyết trình: **`report/PHAN_NOI.md`** (kịch bản nói + câu hỏi phản biện), tóm tắt demo: `report/HUONG_DAN_DEMO.md`.

## Phân công & lỗi

| Thành viên | Lỗi | Vá tại |
|---|---|---|
| Nguyễn Toàn Thắng — B26CHAT039 | F01 SQL injection đăng nhập | `routes/login.ts` |
| Phạm Thị Minh Thúy — B26CHAT042 | F02 IDOR giỏ hàng | `routes/basket.ts` |
| Đỗ Đức Quốc Anh — B26CHAT001 | F03 lộ `/metrics` không xác thực | `docker-compose.yml`, `deploy/nginx.conf`, `policy/compose.rego` |
| Hồ Anh Vũ — B26CHAT048 | F04 sai cấu hình container (Policy as Code) | `policy/docker_security.rego` |

## Nội dung thư mục `report/`

| Đường dẫn | Mô tả |
|---|---|
| `DEMO.md` | Runbook đầy đủ: khởi động + chạy mọi demo + các cổng kiểm soát |
| `HUONG_DAN_DEMO.md` | Bản tóm tắt nhanh theo từng lỗi |
| `PHAN_NOI.md` | Kịch bản thuyết trình + 12 câu hỏi phản biện |
| `BaoCao_...gon.pdf` / `report_concise.md` | Báo cáo (PDF) và nguồn Markdown |
| `demos/` | 4 script demo (`tv1`–`tv4`) + `common.py` |
| `checks/hardening.py` | Bảng cấu hình an toàn container đang chạy (ảnh `hardening.png`) |
| `policy/` | Luật Rego kiểm tra container runtime (`docker inspect`) |
| `semgrep-rules/` | Luật Semgrep dùng cho SAST (F01/F02) |
| `fixtures/` | Dockerfile/compose mẫu để đối chứng policy |
| `screenshots/` | Ảnh minh chứng dùng trong báo cáo |

> Chính sách build-time (Dockerfile F04 + compose F03) nằm ở `policy/` tại **gốc repo**, không phải trong `report/policy/`
> (thư mục `report/policy/` chỉ chứa luật kiểm tra **runtime**).
