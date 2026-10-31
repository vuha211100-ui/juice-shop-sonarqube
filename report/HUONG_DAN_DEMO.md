# Hướng dẫn demo bốn lỗi F01–F04

Báo cáo: `report/BaoCao_DevSecOps_JuiceShop_gon.pdf`.
**Runbook đầy đủ (khởi động + chạy tất cả demo): `report/DEMO.md`.** File này tóm tắt nhanh.
Chạy mọi lệnh tại **thư mục gốc repo** (clone xong là ở nhánh `main` — không cần checkout gì).

## Chuẩn bị

```powershell
# Nhánh mặc định 'main' đã là báo cáo lần này (clone xong là ở main).
docker start juice-report-lab        # TRƯỚC vá: image gốc, 127.0.0.1:3100 (lần đầu xem DEMO.md mục 1)
docker compose up -d --build         # SAU vá: proxy 127.0.0.1:3102 (project 'juice-app')
docker compose ps
```

Mỗi demo chạy cùng một kịch bản trên cả hai môi trường và in bảng trước/sau.

| Thành viên | Lệnh | Điểm cần giải thích |
|---|---|---|
| F01 SQL injection (Nguyễn Toàn Thắng) | `python report/demos/tv1_f01_sqli.py` | Trước vá payload được cấp token; sau vá 401. Code vá: `routes/login.ts` |
| F02 Poison Null Byte (route tải tệp) (Phạm Thị Minh Thúy) | `python report/demos/tv2_f02_pathtraversal.py` | trước vá null byte đọc tệp sao lưu; sau vá 403. Code vá: `routes/fileServer.ts` |
| F03 /metrics (Đỗ Đức Quốc Anh) | `python report/demos/tv3_f03_metrics.py` | 3100/metrics lộ; 3102/metrics 404; cổng 3101 refused; giám sát nội bộ vẫn đọc được. Cấu hình: `docker-compose.yml`, `deploy/nginx.conf`, policy `policy/compose.rego` |
| F04 Sai cấu hình container / Policy as Code (Hồ Anh Vũ) | `python report/demos/tv4_f04_policy.py` | Dockerfile.vulnerable bị chặn 4 nhóm luật; bản vá, hotfix và **Dockerfile gốc đều đạt chính sách**. Policy: `policy/docker_security.rego` (theo lab ConfTest + luật riêng SECRET-IN-IMAGE) |

## Các cổng kiểm soát (Security as Code / Policy as Code)

```powershell
# SAST (Semgrep) phát hiện F01/F02
docker run --rm -e SEMGREP_SEND_METRICS=off -v "${PWD}:/src:ro" -v "${PWD}/report/semgrep-rules:/rules:ro" `
  semgrep/semgrep:1.180.0 semgrep scan --metrics=off --quiet --config /rules/owasp-top-ten.yml --config /rules/nodejsscan.yml /src/routes/login.ts /src/routes/fileServer.ts

# Quét secret (Gitleaks)
docker run --rm -v "${PWD}:/repo:ro" zricethezav/gitleaks:v8.30.1 git /repo --log-opts="baf9dcea4..HEAD" --no-banner
# baf9dcea4 = commit gốc trước khi vá; quét 14 commit F01–F04 sau nó (đừng dùng main..fix/f01-f04 — nay rỗng)

# Policy as Code (Conftest/OPA) — unit test toàn bộ luật -> 19/19
docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 verify -p policy --no-color
```

## Kiểm thử bảo mật (đỏ trước vá, xanh sau vá)

```powershell
git checkout 21219d66d -- routes        # lấy tạm route chưa vá -> một số ca đỏ
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
git checkout HEAD -- routes             # trả lại bản vá -> toàn bộ ca xanh
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
```
