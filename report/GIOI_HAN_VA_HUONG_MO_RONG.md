# Giới hạn và hướng mở rộng

Tài liệu đi kèm báo cáo chính (`report_concise.md`). Báo cáo chính tập trung nêu **kết quả**; các giới hạn về phạm vi thực nghiệm và hướng mở rộng được tách ra đây để giữ phần kết quả gọn và rõ.

## 1. Phạm vi môi trường (lab)

- Thực nghiệm chạy trong môi trường lab: cổng chỉ bind loopback (`127.0.0.1`), chưa phải tình huống phơi ra Internet; container đối chứng `3100` (image gốc) chỉ phục vụ so sánh trước/sau vá.
- HTTP nội bộ giữa reverse proxy và backend chưa bật TLS.
- Base image chưa ghim theo digest — luật Rego hiện mới **cảnh báo**, chưa bắt buộc trên image đối chứng.
- Stack giám sát (compose riêng) mở `127.0.0.1:9090` (Prometheus) và `127.0.0.1:3103` (Grafana); Grafana bật **anonymous access vai trò Admin** phục vụ demo — là ngoại lệ lab, cần tắt hoặc giới hạn khi triển khai thật. Hai dịch vụ dùng tag `latest`, chưa có bộ hardening tương đương stack ứng dụng và chưa được `compose.rego` kiểm. Vì vậy phát biểu "chỉ reverse proxy publish cổng" chỉ đúng cho **stack ứng dụng**; ranh giới tin cậy đầy đủ cần tính cả cổng giám sát và người dùng quản trị lab.

## 2. Theo từng tình huống

- **F02 (Poison Null Byte):** mới kiểm chứng với 2 payload null byte; chưa quét toàn bộ biến thể chuẩn hóa đường dẫn hay toàn bộ chính sách công bố tệp. Thực nghiệm chỉ chứng minh đọc được tệp *bên trong* thư mục `ftp/`, không truy cập ra ngoài thư mục này.
- **F03 (`/metrics`):** các chỉ số là số liệu tổng hợp vận hành, chưa phải dữ liệu cá nhân định danh; phạm vi kiểm chứng là *truy cập từ host*. Giám sát backend chỉ quan sát phản hồi **hoàn tất tại backend**; yêu cầu bị Nginx chặn ngay tại proxy (429 rate-limit, 404 cho `/metrics`) không tới backend nên không vào metric này.
- **F04 (cấu hình container):** bộ luật chỉ chứng minh cấu hình đạt *các luật đã định nghĩa*, **không** đồng nghĩa đạt toàn bộ CIS Docker Benchmark. Nhãn nguồn gốc OCI tự khai chỉ dùng để *tham chiếu* SLSA, chưa đánh giá đạt mức.

## 3. Quy trình

- Toàn bộ cổng kiểm soát được viết thành mã và chạy lặp lại được, nhưng **hiện chạy cục bộ** — chưa nối thành *required check* bắt buộc trong CI.
- Báo cáo đã bổ sung quét **SCA (Trivy)** nhưng **chưa đánh giá DAST**; chưa kết luận production-ready.
- Giám sát: luật cảnh báo là **ngưỡng 4XX tổng quát tại backend** (chưa phân biệt endpoint/nguồn); tải thử nghiệm đi **trực tiếp tới backend**, chưa qua proxy. FIRING là *trạng thái của luật* — định tuyến thông báo (Alertmanager) và giám sát rate-limit tại proxy là hướng mở rộng.
- **Xử lý rủi ro CVE (Trivy):** 189 bản ghi (173 CVE duy nhất) chủ yếu là **dependency kế thừa** của ứng dụng cố ý dễ tổn thương; nhóm phân loại là **rủi ro đã biết**, hướng xử lý là nâng cấp dependency khi triển khai thật — vá toàn bộ nằm ngoài phạm vi bốn tình huống.
- Kho mã Juice Shop gốc đã có sẵn CI/CD, CodeQL và tạo SBOM; đóng góp của nhóm là các kiểm soát **bổ sung, hướng dữ liệu cá nhân**, không nhằm thay thế tự động hóa sẵn có.

## 4. Hướng mở rộng

- Nối các cổng (Semgrep `--error`, Conftest, Trivy, bộ test) thành **required check** trên pull request.
- Ghim base image theo digest; bật TLS cho kênh nội bộ.
- Mở rộng tập payload (F02) và bộ policy; bổ sung **DAST** cho đánh giá động.
- Đưa giám sát (Prometheus/Grafana/Alertmanager) lên hạ tầng thật với cảnh báo định tuyến đầy đủ.
