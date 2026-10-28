# Ghi chú nội bộ — những điều nhóm cần nắm khi trình bày/bảo vệ

> File này **KHÔNG thuộc báo cáo chính thức**. Đây là phần giải thích để nhóm biết *nói gì* khi thuyết trình hoặc khi bị hỏi. Nội dung dưới đây đã được gỡ khỏi báo cáo để báo cáo giữ giọng khách quan.

## 1. node:test (Supertest) chạy như thế nào

Kiểm thử bảo mật (`test/api/security/f01-f02.test.ts`) chạy ứng dụng thật trong bộ nhớ, không cần container:

```powershell
git checkout 21219d66d -- routes        # lấy tạm route CHƯA vá -> kỳ vọng một số ca ĐỎ
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
git checkout HEAD -- routes             # trả lại bản vá -> kỳ vọng toàn bộ XANH
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
```

Lệnh chạy đầy đủ cho mọi cổng và demo: xem `DEMO.md` (thư mục gốc repo) và `report/HUONG_DAN_DEMO.md`.

## 2. Đoạn mã dò lỗi cốt lõi của mỗi demo (nói khi chiếu demo)

Mỗi script chạy bằng một lệnh `python report/demos/<tên>.py`; phần dò lỗi cốt lõi:

- **F01 — `tv1_f01_sqli.py`:** gửi payload SQL kèm mật khẩu *sai*; còn lỗ hổng nếu vẫn được cấp token.
  `call(base,'POST','/rest/user/login',{'email':"' OR 1=1--",'password':'wrong-password'})` → có `token` = vượt xác thực.
- **F02 — `tv2_f02_idor.py`:** dùng token của A đọc giỏ của B; `s==200 and body['data']['id']==b['bid']` = lộ giỏ người khác.
- **F03 — `tv3_f03_metrics.py`:** gọi `/metrics` — trước vá 200 (lộ), sau vá qua proxy 404.
- **F04 — `tv4_f04_policy.py`:** chạy Conftest trên Dockerfile; thoát khác 0 = gate chặn, mỗi dòng FAIL là một luật bị vi phạm.

## 3. Một luật Rego gồm gì & cách trích chuẩn (nói khi bị hỏi về policy)

Mỗi luật là một mệnh đề Rego: phần *thân* nêu điều kiện vi phạm trên cây cú pháp Dockerfile/compose (ví dụ "stage cuối không có `USER`", "`EXPOSE` chứa cổng 22", "`ENV` chứa từ khóa bí mật"); phần *thông điệp* (`msg`) là lý do trả về. Mã điều khoản chuẩn được nhúng thẳng vào `msg` — ví dụ LEAST-PRIVILEGE trả về *"…container runs as root. (CIS Docker 4.1; PCI-DSS 2.2; NĐ 13/2023 Đ.26; Luật ATTTM 2015 Đ.19)"* — nên khi gate chặn thấy ngay luật nào vi phạm điều khoản nào.

## 4. Phân định nguồn — kế thừa lab vs tự bổ sung (nói khi bị hỏi "tự làm gì")

`docker_security.rego` kế thừa cấu trúc và bốn luật cốt lõi từ Appendix A.1 tài liệu lab (LEAST-PRIVILEGE theo `USER` stage cuối, ATTACK-SURFACE theo cổng cấm, nhãn provenance OCI, SUPPLY-CHAIN `:latest`/digest). Phần bổ sung: (a) bỏ luật HEALTHCHECK/OBSERVABILITY (distroless không chạy được); (b) gộp provenance vào SUPPLY-CHAIN (metadata nguồn gốc tự khai — **chỉ hỗ trợ truy vết, chưa đạt SLSA**); (c) **tự viết luật `SECRET-IN-IMAGE`** chặn secret trong `ENV`/`ARG` (không có trong lab); (d) **sửa lỗ hổng tách UID**: `USER 0:1000` (root kèm group) từng lọt do so khớp nguyên chuỗi, nay tách phần trước dấu `:`; thêm 2 unit test (`0:1000`, `root:1000`) → tổng 13 ca Dockerfile, `conftest verify` 19/19. Khi bị hỏi "Semgrep có phát hiện IDOR không": **không** — Semgrep chỉ phát cảnh báo NoSQLi (CWE-943) làm gợi ý vị trí; IDOR (F02) xác nhận bằng test A/B. `compose.rego` (F03) tự viết cho docker-compose (lab chỉ có k8s.rego).
