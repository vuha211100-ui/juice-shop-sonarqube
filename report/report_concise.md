# Danh mục từ viết tắt

Table: Danh mục từ viết tắt
| Viết tắt | Giải nghĩa |
|---|---|
| SQLi | SQL Injection — tiêm nhiễm câu lệnh SQL |
| JWT | JSON Web Token — token phiên |
| SAST | Phân tích tĩnh mã nguồn (Static Application Security Testing) |
| CI/CD | Tích hợp / triển khai liên tục |
| OPA | Open Policy Agent (ngôn ngữ Rego, công cụ Conftest) |
| GDPR | Quy định bảo vệ dữ liệu của EU (2016/679) |
| PCI-DSS | Chuẩn an toàn dữ liệu thẻ thanh toán |
| CIS | Center for Internet Security (CIS Docker Benchmark) |
| CWE / OWASP | Phân loại điểm yếu phần mềm / tổ chức an toàn ứng dụng web |
| UID | Mã định danh người dùng hệ điều hành |

# 1. Giới thiệu và phạm vi

Báo cáo đánh giá an toàn ứng dụng **OWASP Juice Shop v20.2.0** dưới góc độ bảo vệ dữ liệu người dùng qua **bốn tình huống**. Bốn thành viên thực hiện, mỗi người phụ trách một tình huống: hai lỗi ở mã nguồn (F01, F02), một rủi ro phơi nhiễm ở khâu vận hành (F03) và một fixture cấu hình sai chủ động dựng để kiểm tra chính sách (F04). Mỗi tình huống được trình bày theo mạch **trước khi sửa → sau khi sửa**, gồm cách phát hiện, cách xử lý, nguyên tắc/tiêu chuẩn đối chiếu, pha DevSecOps tương ứng và đoạn mã demo.

Mỗi kịch bản được chạy song song trên hai môi trường để đối chiếu: bản **trước khi sửa** là container chạy image gốc (127.0.0.1:3100), còn bản **sau khi sửa** là bản triển khai đã qua reverse proxy (127.0.0.1:3102). Bên trong container, cổng 3000 là cổng mặc định của Juice Shop; bản đã xử lý vẫn lắng nghe cổng này nhưng không phơi ra host, chỉ reverse proxy (cổng 3102) truy cập được qua mạng nội bộ. Cổng 3100 dành cho container đối chứng chạy image gốc để so sánh. Juice Shop là ứng dụng cố ý chứa lỗ hổng phục vụ huấn luyện; các phát hiện ở đây minh họa quy trình, không nhằm đánh giá dự án gốc.

# 2. Ứng dụng Juice Shop và dữ liệu cần bảo vệ

Juice Shop là một ứng dụng web thương mại điện tử mô phỏng (bán nước ép) do OWASP phát hành nhằm huấn luyện an toàn ứng dụng. Về kiến trúc, đây là một Single Page Application gồm các thành phần sau:

Table: Thành phần của ứng dụng Juice Shop
| Thành phần | Công nghệ | Vai trò |
|---|---|---|
| Giao diện người dùng | Angular (SPA) | Hiển thị, gọi REST API |
| Máy chủ ứng dụng | Node.js + Express | Xử lý REST API và nghiệp vụ |
| Truy xuất dữ liệu | ORM Sequelize trên SQLite | Lưu Users, Baskets, Cards… |
| Xác thực phiên | JWT (RS256), thư viện jsonwebtoken | Cấp và kiểm tra token đăng nhập |
| Giám sát | prom-client, endpoint `/metrics` | Xuất chỉ số dạng Prometheus |
| Đóng gói | Docker image distroless, chạy UID 65532 | Triển khai bằng container |

Cả bốn lỗi được phân tích đều gắn với những thành phần này: REST API/ORM (F01), route phục vụ tệp tĩnh (F02), endpoint giám sát (F03) cùng cách đóng gói container (F04). Yêu cầu bảo vệ dữ liệu được xác định theo GDPR (nguyên tắc ở Điều 5, nghĩa vụ an toàn ở Điều 32) và PCI-DSS cho dữ liệu thẻ thanh toán (chi tiết ở mục 3.2).

Table: Dữ liệu cần bảo vệ và cơ sở chính sách
| Dữ liệu | Yêu cầu bảo vệ | Cơ sở chính sách |
|---|---|---|
| Email, hồ sơ | Chỉ chủ tài khoản/quản trị truy cập | GDPR Điều 5(1)(f), 25(2) |
| Mật khẩu | Không để lộ; không bị vượt xác thực | GDPR Điều 32(1)(b) |
| Token phiên (JWT) | Chỉ cấp khi xác thực đúng | GDPR Điều 32(1)(b) |
| Giỏ hàng | Ràng buộc chủ sở hữu ở mọi truy vấn | GDPR Điều 5(1)(f), 25(2) |
| Thẻ thanh toán | Không lộ số thẻ; PAN nếu lưu phải ở dạng không đọc được | PCI-DSS 3.4; GDPR Điều 32 |
| Tệp cấu hình, sao lưu phía máy chủ | Không để tải về qua endpoint phục vụ tệp tĩnh | GDPR Điều 32(1)(b) (liên quan F02) |

Ý nghĩa cụ thể của từng điều khoản (GDPR, PCI-DSS… và các chuẩn khác) được tóm gọn trong **Phụ lục C**.

## 2.1. Nghiệp vụ đăng ký và đăng nhập

Người dùng đăng ký qua `POST /api/Users` và đăng nhập qua `POST /rest/user/login`. Route `routes/login.ts` truy vấn bảng Users, nếu khớp thì cấp JWT kèm mã giỏ hàng. Vấn đề nằm ở ranh giới tin cậy: email do client gửi lên đi thẳng vào câu lệnh SQL, và đó chính là gốc của lỗi **F01**.

## 2.2. Nghiệp vụ tải tệp tài liệu

Ứng dụng cho phép tải tệp tài liệu trong thư mục `ftp/` qua `GET /ftp/:file`, chỉ cho phép đuôi `.md`/`.pdf`. Route `routes/fileServer.ts` xử lý yêu cầu này. Thư mục `ftp/` còn chứa một số tệp **không nên để tải về** (bản sao lưu cấu hình, mã giảm giá…). Nếu bộ lọc đuôi file bị qua mặt, người dùng có thể đọc các tệp nhạy cảm đó — và đây là gốc của lỗi **F02**.

# 3. Môi trường triển khai và yêu cầu an toàn tối thiểu

Ứng dụng chạy bằng Docker trên Windows (WSL2) và được triển khai qua `docker-compose.yml`. Các yêu cầu an toàn tối thiểu ở đây bám theo CIS Docker Benchmark cùng nguyên tắc giảm bề mặt tấn công.

Để mỗi kết luận truy được về dữ liệu, thực nghiệm cố định các biến sau và chỉ thay đúng phần cần kiểm chứng (F01/F02 giữ nguyên seed/harness, chỉ thay route; F03 giữ logic ứng dụng, chỉ thay cấu hình truy cập; F04 chạy fixture trước/sau độc lập):

Table: Phương pháp thực nghiệm
| Hạng mục | Giá trị cố định |
|---|---|
| Phiên bản mã trước khi vá | Bản mã Juice Shop gốc (thư mục `routes/`, `lib/` chưa chỉnh) — dùng để quét Semgrep và chạy ca kiểm thử đỏ |
| Phiên bản mã sau khi vá | Bản vá của nhóm, đóng gói trong image hotfix triển khai ở cổng 3102 |
| Hai môi trường | Đối chứng `127.0.0.1:3100` (image gốc) ↔ triển khai `127.0.0.1:3102` (proxy + backend mạng internal) |
| Dữ liệu thử nghiệm | Bộ dữ liệu mẫu Juice Shop tự nạp khi khởi động (người dùng, giỏ hàng, sản phẩm giả lập) |
| Công cụ (phiên bản) | Semgrep 1.180.0; Gitleaks v8.30.1; Conftest/OPA v0.71.1; node:test + Supertest; Trivy 0.76.1; Dockle 0.4.15; Prometheus 3.15.1; Grafana 13.3.0 |
| Tiêu chí đạt | F01/F02: ca kiểm thử xanh; F03: `/metrics` trả 404 từ ngoài; F04: conftest `exit 0` với bản tốt, `exit 1` với fixture lỗi |
| Bằng chứng | `report/evidence/*.log` (kèm exit code), kiểm thử, demo (tổng hợp ở mục 4.2) |

Table: Kiểm soát an toàn tối thiểu
| Kiểm soát | Cách thực hiện | Tiêu chuẩn |
|---|---|---|
| Giảm bề mặt mạng | Chỉ reverse proxy publish cổng của **stack ứng dụng**, trên 127.0.0.1; backend ở mạng internal | GDPR Điều 32 |
| Không chạy root | Juice Shop UID 65532, Nginx UID 101 | CIS Docker 4.1 |
| Đặc quyền tối thiểu | `cap_drop: ALL`, `no-new-privileges`; hệ thống tệp gốc đặt chế độ chỉ đọc ở các service hỗ trợ | CIS Docker 5.3/5.12 |
| Ghim phiên bản | Luật Rego chặn `:latest`, cảnh báo khi base image chưa ghim digest | CIS Docker Benchmark §4 |
| Lọc đường vào | Nginx chặn /metrics, giới hạn 5 lần đăng nhập/phút | GDPR Điều 32 |

Những kiểm soát này được **xác minh ngay trên container đang chạy** bằng `docker inspect` (Compliance as Code), cho thấy chúng thực sự có hiệu lực chứ không chỉ nằm trên file cấu hình:

!fig[hardening.png](Bằng chứng runtime qua `docker inspect`: cả ba container chạy non-root (USER), `cap_drop: ALL`, `no-new-privileges`; backend không mở cổng host (CỔNG HOST = “-”, mạng internal), chỉ proxy mở loopback 127.0.0.1:3102){width=16}

## 3.1. Công cụ sử dụng

Table: Công cụ và vai trò
| Công cụ | Loại | Vai trò trong báo cáo |
|---|---|---|
| Docker, Docker Compose | Nền tảng container | Triển khai ứng dụng và môi trường kiểm thử |
| Nginx | Reverse proxy | Chặn /metrics, giới hạn tốc độ đăng nhập (F03) |
| Semgrep | SAST (phân tích tĩnh) | Đọc mã nguồn (không chạy) để chỉ ra các mẫu lỗi; trong phạm vi báo cáo, xác định chính xác dòng SQL injection của F01 (đăng nhập) và Poison Null Byte của F02 (route tải tệp) |
| Gitleaks | Quét secret | Tìm khóa/bí mật lộ trong mã nguồn |
| node:test (Supertest) | Kiểm thử động | Chạy ứng dụng thật, tái hiện lỗi *trước khi vá* (đỏ) và kiểm chứng *sau khi vá* (xanh) |
| Conftest / OPA (Rego) | Policy as Code | Kiểm tra *văn bản* Dockerfile và cấu hình triển khai (pha Build/Deploy, F03/F04) |
| Trivy | Quét image (SCA) | Quét CVE dependency + secret + misconfig trên **image đã build** (pha Release); bổ sung mảng SCA mà các công cụ trên không có |
| Dockle | Lint image (CIS) | Kiểm cấu hình **image sau build** theo CIS Docker — bắt secret bake vào layer (tệp & `ENV`) và user chạy thật/root (pha Release) |
| Prometheus + Grafana | Giám sát (Operate) | Thu thập `/metrics` nội bộ, cảnh báo bất thường, dashboard vận hành |

## 3.2. Chính sách và tiêu chuẩn đối chiếu

Báo cáo đối chiếu các **tiêu chuẩn quốc tế** về bảo vệ dữ liệu cá nhân; ngưỡng và luật Rego cụ thể do nhóm thiết kế cho môi trường lab. Phần thân chỉ ghi **mã điều khoản** — **ý nghĩa (yêu cầu gì) của mọi điều khoản tra tại Phụ lục C**.

- GDPR (EU) 2016/679 — Điều 5, 25, 32; PCI-DSS — Yêu cầu 2.2, 3.4, 8.2.1; OWASP Top 10 2021 & CWE — A03/CWE-89 (F01), A01/CWE-158 + CWE-180 (F02); CIS Docker Benchmark — 4.1, 4.9, 4.10, 5.3, 5.4, 5.8, 5.12 (F04); OCI image-spec, NIST SP 800-190, NIST SSDF (SP 800-218), SLSA (chuỗi cung ứng — chỉ *tham chiếu*, không tuyên bố đạt mức).

Với dữ liệu giả lập của ứng dụng huấn luyện, báo cáo dùng cách diễn đạt *"đối chiếu nguyên tắc bảo vệ"* thay cho kết luận tuân thủ pháp luật.

# 4. Quy trình DevSecOps và các cổng kiểm soát

Việc phát hiện và chống tái diễn cả bốn lỗi đều được viết thành mã và chạy tự động dưới dạng một chuỗi kiểm soát (pipeline cục bộ) theo mô hình DevSecOps. Hình dưới ánh xạ từng lỗi và **năm lớp cổng kiểm soát** vào các pha trong vòng đời DevSecOps — Security as Code (xanh dương, F01/F02), Policy as Code (xanh lá, F03/F04), quét image Trivy/Dockle (cam, Release) và giám sát Prometheus/Grafana (tím, Operate):

!fig[devsecops-pipeline.png](Quy trình DevSecOps: ánh xạ bốn lỗi F01–F04 và năm lớp cổng kiểm soát theo từng pha — Security as Code (F01/F02), Policy as Code (F03/F04), quét image Trivy/Dockle (Release), Compliance as Code và giám sát Prometheus/Grafana (Operate)){width=16}

Các lớp kiểm soát, xếp theo **pha vòng đời** (mỗi lớp bắt loại lỗi lớp khác không thấy):

- **Security as Code (Code/Test):** quét secret (Gitleaks), SAST (Semgrep) cho F01/F02, và kiểm thử bảo mật `f01-f02.test.ts` (đỏ trước vá, xanh sau vá).
- **Policy as Code (Build/Deploy):** luật Rego cho Dockerfile (F04) và `docker-compose` (F03), chặn ngay cấu hình mở cổng backend hoặc chạy root **trước khi triển khai** — đọc *văn bản* cấu hình.
- **Quét image (Release):** **Trivy** quét CVE dependency (SCA) và **Dockle** lint cấu hình image theo CIS trên **image đã build** — bắt lỗ hổng thư viện và secret bị bake vào layer mà quét văn bản không thấy (mục 4.1).
- **Compliance as Code (Operate):** kiểm **container đang chạy** bằng `docker inspect` + luật Rego runtime, xác nhận non-root, drop capability, chỉ proxy mở cổng loopback. Đặt container đối chứng (trước vá) cạnh bản triển khai (sau vá) tạo đúng cặp ca *lỗi cố ý / đạt*.
- **Giám sát vận hành (Operate):** **Prometheus** scrape `/metrics` nội bộ, **Grafana** dashboard, và **cảnh báo** khi có bất thường (vd đột biến 4XX do dò đăng nhập) — mục 4.3.

Toàn bộ kiểm soát được viết thành mã nên chạy lặp lại được trên **hai môi trường song song**: container đối chứng *trước vá* (`127.0.0.1:3100`) và bản triển khai *sau vá* qua reverse proxy (`127.0.0.1:3102`, backend ở mạng internal).

Quy trình bám theo **bảy pha** của bài lab môn học *Security as Code with OWASP Juice Shop & Docker*. Nhóm giữ nguyên trình tự bảy pha và mở rộng cho phù hợp phạm vi dữ liệu cá nhân: thêm quét **SCA (Trivy)** ở pha 3, kiểm **image theo CIS (Dockle)** ở pha 6, và **giám sát vận hành** (theo lab *Telemetry*) ở pha 7. Hình trên ánh xạ các cổng này lên vòng đời DevSecOps.

Table: Bảy pha thực hành (theo lab Security as Code) ánh xạ vào bốn tình huống
| Pha | Hoạt động | Công cụ nhóm dùng | Tình huống |
|---|---|---|---|
| 1. Thiết lập môi trường | Dựng hai môi trường trước/sau vá (3100 đối chứng, 3102 proxy) | Docker Compose, Node.js | — |
| 2. Policy as Code | Kiểm chính sách Dockerfile + compose **trước** khi triển khai | Conftest/OPA (Rego) | F03, F04 |
| 3. Phát hiện điểm yếu & ánh xạ điều khoản | Quét tĩnh mã nguồn (SAST) + quét CVE dependency (SCA), gắn với GDPR/PCI-DSS/CWE | Semgrep, Trivy | F01, F02 |
| 4. Test-Driven Security | Kiểm thử đỏ trước vá, xanh sau vá | node:test + Supertest | F01, F02 |
| 5. Vá ứng dụng | Sửa mã theo kết quả kiểm thử | TypeScript / Express | F01, F02 |
| 6. Compliance as Code | Kiểm image thành phẩm (CIS) và **container đang chạy** — thay Chef InSpec của lab bằng `docker inspect` + Conftest runtime + Dockle | Dockle, `docker inspect`, Conftest | F03, F04 |
| 7. Kiểm chứng & bàn giao | Chạy lại toàn bộ cổng + quét secret; **giám sát vận hành** (mở rộng theo lab Telemetry) | Gitleaks, Conftest; Prometheus/Grafana | — |

Hai cổng kiểm soát bổ trợ đều cho **exit 0** (log gốc kèm thời điểm, phiên bản công cụ, mã thoát): **Gitleaks** quét các commit vá của nhóm — không phát hiện secret (`gitleaks.log`); **Conftest verify** — 19/19 unit test của bộ luật Rego đạt, gồm 13 ca Dockerfile và 6 ca compose (`conftest-verify.log`).

Mỗi lỗi đi kèm một script demo (`demos/tv1`…`tv4`) tái hiện lỗi trước khi vá và kiểm chứng sau khi vá; các script này được trình bày trong từng mục tương ứng ở phần 5.

## 4.1. Quét và phát hiện lỗi — kết quả thực tế

Các cổng quét tự động được chạy trên mã nguồn và cấu hình *chưa vá* để lộ ra điểm yếu trước khi sửa.

**SAST (Semgrep).** Quét toàn bộ `routes/` và `lib/` (mã *chưa vá*) cho ra **38 cảnh báo** trên 25 tệp (SQL/NoSQL injection, XSS, băm yếu, JWT secret cố định…). Đây là **cảnh báo công cụ, chưa phải 38 lỗ hổng đã xác nhận**; mỗi cảnh báo là một điểm cần rà soát thêm. Thuộc phạm vi báo cáo, phân tích tĩnh chỉ ra hai điểm: **F01** tại `login.ts` (rule `express-sequelize-injection` — SQL injection ở đăng nhập) và **F02** tại `fileServer.ts` (rule `express-res-sendfile` — Poison Null Byte, lộ tệp sao lưu).

!fig[semgrep-scan.png](Hai điểm Semgrep xác định trong phạm vi: F01 SQL injection ở đăng nhập (`login.ts`) và F02 Poison Null Byte (`fileServer.ts`); kèm phân loại của nhóm){width=16}

**Policy as Code (Conftest).** Quét `Dockerfile.vulnerable` cho `exit 1` với **6 thông báo vi phạm thuộc 4 nhóm luật** `deny` — mã thoát này đủ điều kiện làm cổng chặn (chi tiết F04 ở mục 5.4):

!fig[conftest-fail.png](Conftest quét Dockerfile.vulnerable: `exit 1`, 6 thông báo vi phạm thuộc 4 nhóm luật `deny`; mã thoát đủ để làm cổng chặn){width=16}

**Quét image — CVE/SCA (Trivy, pha Release).** Trên image triển khai `juice-shop:hotfix-f01-f02`, Trivy quét lỗ hổng *dependency*: **189 bản ghi phát hiện** (173 mã CVE duy nhất; 12 CRITICAL, 56 HIGH, 97 MEDIUM, 24 LOW) — gồm các thư viện cũ như `crypto-js` (CVE-2023-46233, CRITICAL), `jws`, `body-parser`, `brace-expansion`. Đây là **mảng SCA** mà Semgrep (quét mã nhóm tự viết) và Conftest (quét cấu hình) **không phủ**. Các CVE này chủ yếu đến từ **dependency kế thừa** của một ứng dụng cố ý dễ tổn thương; nhóm ghi nhận là **rủi ro đã biết**, xử lý bằng nâng cấp dependency khi triển khai thật — vá toàn bộ nằm ngoài phạm vi bốn tình huống (JSON gốc: `report/evidence/trivy-image.json`) (@fig(trivy)).

!fig[trivy.png](Trivy quét lỗ hổng dependency của image hotfix: 189 bản ghi (173 CVE duy nhất; 12 CRITICAL, 56 HIGH); SCA là lớp mà SAST/Policy-as-Code không phủ){width=16}

**Quét image — CIS (Dockle, pha Release).** Dockle đọc *image đã build* (không phải văn bản Dockerfile) nên bắt được lỗi chỉ lộ ở thành phẩm. Để kiểm chứng ngay **trên image Juice Shop**, nhóm lấy chính image triển khai rồi chồng thêm cấu hình sai (chạy root, COPY `id_rsa`, secret trong `ENV`) thành một image Juice Shop đóng gói sai. Trên image này, Dockle báo **FATAL** (`CIS-DI-0010`) cho **cả secret nằm trong tệp bị COPY vào layer** (`id_rsa` — dữ liệu giả lập) **lẫn secret trong `ENV`** (`API_TOKEN`), kèm **WARN** chạy root (`CIS-DI-0001`); còn image triển khai của nhóm **không có FATAL/WARN** (chỉ còn INFO và một kiểm tra bị bỏ qua do không đọc được `/etc/shadow`). Hai công cụ **giao nhau** ở secret trong `ENV` và chạy root — cả Conftest lẫn Dockle đều bắt; phần **riêng** của Dockle là secret trong *tệp* và các thuộc tính chỉ thấy ở *image thành phẩm*. Conftest kiểm *công thức* trước build, Dockle kiểm *thành phẩm* sau build (@fig(dockle)).

!fig[dockle.png](Dockle quét trên image Juice Shop: bản đóng gói sai bị FATAL (secret trong tệp id_rsa giả lập + secret ENV) và WARN chạy root; image triển khai của nhóm không có FATAL/WARN){width=16}

## 4.2. Bảng kết quả hợp nhất

Bảng dưới liên kết từng tình huống với kết quả và **tệp bằng chứng** tương ứng (log gốc trong `report/evidence/`, kiểm thử, demo).

Table: Kết quả hợp nhất bốn tình huống (điều kiện → kỳ vọng → trước/sau vá → bằng chứng)
| Mã | Điều kiện kiểm thử | Kết quả mong đợi | Trước vá | Sau vá | Bằng chứng |
|---|---|---|---|---|---|
| F01 | Đăng nhập bằng payload SQL + mật khẩu sai | Từ chối (401) | Cấp token, vượt xác thực | 401; đăng nhập hợp lệ vẫn 200 | `f01-f02.test.ts`; demo `tv1`; `semgrep-overview.log` |
| F02 | `GET /ftp/<tên>%2500.md` (poison null byte) | Từ chối tệp đuôi bị cấm | Đọc được `package.json.bak`, `coupons_2013.md.bak` | 403; tệp `.md` hợp lệ vẫn tải | `f01-f02.test.ts`; demo `tv2`; `tv2-f02.log` |
| F03 | `GET /metrics` từ host | Chặn truy cập từ ngoài | 200, lộ chỉ số vận hành | 404 qua proxy; backend không mở cổng host | demo `tv3`; `env-*.log`; `hardening` |
| F04 | Conftest trên fixture lỗi / bản vá / Dockerfile gốc | Chặn fixture lỗi, đạt bản tốt | Fixture: `exit 1`, 6 vi phạm / 4 nhóm | Bản vá & gốc: đạt; `verify` 19/19 | `conftest-fail.log`; `conftest-verify.log`; demo `tv4` |

Các chỉ số ở F03 là số liệu tổng hợp, chưa phải dữ liệu cá nhân định danh; F04 là fixture cố ý lỗi, không phải lỗi image gốc.

## 4.3. Giám sát khi vận hành (pha Operate)

Các lớp trên dừng ở "trước khi chạy" và "cấu hình lúc chạy". Khi ứng dụng **đang chạy**, nhóm bổ sung một lớp **quan sát + phát hiện** nhẹ: **Prometheus** scrape endpoint `/metrics` của ứng dụng qua **mạng nội bộ** (app vẫn không mở cổng host — đúng nguyên tắc F03), **Grafana** làm portal hiển thị, và một **luật cảnh báo** để phát hiện bất thường.

Chính `/metrics` mà F03 chặn ra ngoài lại là *nguồn cấp dữ liệu giám sát nội bộ*: nó xuất số người dùng, số đơn hàng, thời gian xử lý HTTP và số phản hồi theo mã trạng thái. Prometheus scrape endpoint này (target **UP**), Grafana vẽ thành dashboard vận hành (@fig(grafana-dashboard)).

!fig[grafana-dashboard.png](Dashboard Grafana (portal giám sát) với số liệu thật từ ứng dụng đang chạy: người dùng đã đăng ký, đơn hàng, HTTP theo status_code, RAM tiến trình){width=16}

Phần **phát hiện**: luật cảnh báo `HighClientErrorRate` theo dõi **số phản hồi 4XX tại backend** (ngưỡng `>20` trong 2 phút). Khi nhóm gửi 60 yêu cầu đăng nhập sai **trực tiếp tới backend** (mô phỏng dò mật khẩu), số 4XX vọt lên và cảnh báo **chuyển trạng thái FIRING** (@fig(monitoring)) — minh họa khả năng phát hiện bất thường ở tầng quan sát mà mã nguồn không tự biết. Đây là ngưỡng tổng quát trên backend (chưa phân biệt endpoint hay nguồn truy cập); FIRING là *trạng thái của luật*, còn việc giám sát các yêu cầu bị Nginx chặn ngay tại proxy (vd rate-limit 429) và định tuyến thông báo tới người vận hành (Alertmanager) thuộc hướng mở rộng (xem *Giới hạn*).

!fig[monitoring.png](Giám sát vận hành: Prometheus scrape /metrics (target UP), truy vấn số liệu thật, và cảnh báo HighClientErrorRate chuyển FIRING khi mô phỏng dò đăng nhập){width=16}

*Lưu ý ranh giới:* stack giám sát mở thêm hai cổng loopback cho người vận hành — `127.0.0.1:9090` (Prometheus) và `127.0.0.1:3103` (Grafana, bật anonymous access phục vụ demo lab) — và chạy ở compose riêng chưa thuộc phạm vi `compose.rego`. Vì vậy phát biểu "chỉ reverse proxy publish cổng" ở mục 3 áp dụng cho **stack ứng dụng**; ranh giới tin cậy đầy đủ (gồm cổng giám sát và người dùng quản trị lab) được nêu trong *Giới hạn*.

## 4.4. Lệnh quét (tái lập)

Các lệnh **quét** của từng cổng kiểm soát được gom ở đây để tái lập, **tách riêng** với các script demo tấn công/khắc phục (`tv1`–`tv4` ở phần 5). Mỗi lệnh chạy ra log gốc kèm mã thoát trong `report/evidence/`.

```bash
# (Code)         SAST — quét mã nguồn bằng bộ luật của nhóm (report/semgrep-rules/)
semgrep scan --config report/semgrep-rules/owasp-top-ten.yml \
             --config report/semgrep-rules/nodejsscan.yml routes/ lib/
# (Code)         quét secret trong lịch sử commit
gitleaks git /repo --log-opts=<range> --no-banner
# (Build/Deploy) Policy as Code — quét VĂN BẢN Dockerfile + compose
conftest test Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile
conftest test docker-compose.yml                         -p policy --namespace compose
conftest verify -p policy                                 # unit test bộ luật Rego (19/19)
# (Release)      quét IMAGE đã build
trivy  image --scanners vuln juice-shop:hotfix-f01-f02    # CVE / SCA
dockle juice-shop:hotfix-f01-f02                          # CIS image (secret tệp & ENV, user)
# (Operate)      Compliance as Code + giám sát
docker inspect <container>                                # -> đưa JSON vào Conftest runtime
curl http://127.0.0.1:9090/api/v1/targets                # Prometheus scrape /metrics
curl http://127.0.0.1:9090/api/v1/alerts                 # trạng thái cảnh báo
```

Ảnh được dựng lại từ chính các lệnh này: `report/figures/capture_runs.py` (Semgrep/Gitleaks/Conftest/docker inspect) và `report/figures/capture_scans.py` (Trivy/Dockle/Prometheus).

# 5. Bốn lỗi an toàn: phát hiện và xử lý

## 5.1. F01 — SQL injection tại đăng nhập

### Trước khi sửa

Route `routes/login.ts` ghép thẳng email vào câu SQL:

```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}'
  AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

Với email `' OR 1=1--`, mệnh đề WHERE luôn đúng còn phần kiểm tra mật khẩu bị đẩy thành chú thích, nên máy chủ cấp token của tài khoản đầu tiên (tài khoản quản trị) mà không cần mật khẩu. Đây chính là CWE-89, OWASP A03:2021.

**Phát hiện.** Semgrep (luật `express-sequelize-injection`) chỉ đúng dòng lỗi (xem hình quét tổng ở mục 4.1). Kiểm thử `test/api/security/f01-f02.test.ts` gửi payload kèm mật khẩu sai và yêu cầu phản hồi 401; trên mã chưa sửa, test báo đỏ (@fig(f0102-red)). Demo `demos/tv1_f01_sqli.py` xác nhận token vẫn được cấp (@fig(tv1)).

!fig[f0102-red.png](Kiểm thử bảo mật F01/F02 trên mã chưa sửa: các ca kiểm thử đỏ ứng với lỗ hổng còn tồn tại){width=15}

### Sau khi sửa

Dùng truy vấn tham số (bind parameter):

```typescript
const email = typeof req.body.email === 'string' ? req.body.email : ''
const password = typeof req.body.password === 'string' ? req.body.password : ''
models.sequelize.query('SELECT * FROM Users WHERE email = $email AND password = $password AND deletedAt IS NULL',
  { bind: { email, password: security.hash(password) }, model: UserModel, plain: true })
```

Câu lệnh được biên dịch trước và giá trị truyền riêng, nên mọi ký tự SQL trong email giờ chỉ còn được hiểu là dữ liệu. Sau khi sửa, kiểm thử bảo mật xanh toàn bộ (@fig(f0102-green)); demo cũng cho thấy mọi payload đều bị từ chối 401 trong khi đăng nhập hợp lệ vẫn hoạt động bình thường (@fig(tv1)).

!fig[tv1.png](Demo F01: cùng payload, trước khi sửa được cấp token, sau khi sửa bị từ chối){width=15}

**Nguyên tắc/tiêu chuẩn đối chiếu:** GDPR Điều 32(1)(b) (bảo mật khi xử lý dữ liệu). **Pha DevSecOps:** Code → Test. **Kiểm soát (Security as Code):** phát hiện bằng SAST ở pha Code, chặn tái diễn bằng kiểm thử bảo mật tự động ở pha Test.

## 5.2. F02 — Poison Null Byte làm lộ tệp sao lưu

### Trước khi sửa

Route `routes/fileServer.ts` phục vụ tệp trong thư mục `ftp/` qua `GET /ftp/:file`. Ứng dụng kiểm tra hậu tố `.md`/`.pdf` (ngoài ra có ngoại lệ cho `incident-support.kdbx`), sau đó mới phục vụ:

```typescript
if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
  file = security.cutOffPoisonNullByte(file)   // cắt tên tại chuỗi literal "%00" rồi mới phục vụ
  res.sendFile(path.resolve('ftp/', file))
}
```

Điểm yếu nằm ở **thứ tự xử lý**: tên tệp được *kiểm tra* khác với tên *thực sự dùng để đọc*. Với yêu cầu `/ftp/package.json.bak%2500.md`, quá trình giải mã URL tạo tham số `package.json.bak%00.md`; tham số này vượt qua kiểm tra hậu tố `.md`, rồi hàm `cutOffPoisonNullByte` cắt tại chuỗi `%00` thành `package.json.bak` và chuyển cho `res.sendFile`. Nhờ đó người dùng **đọc được các tệp sao lưu phía máy chủ** mà bộ lọc đuôi lẽ ra chặn — ví dụ `package.json.bak` (thông tin cấu hình, phiên bản dependency) hay `coupons_2013.md.bak` (mã giảm giá). Đây là lỗi **Poison Null Byte** (CWE-158; CWE-180 kiểm tra trước khi chuẩn hóa; OWASP A01:2021 Broken Access Control).

**Phát hiện.** Semgrep (luật `express-res-sendfile`) chỉ ra lời gọi `res.sendFile` nhận tên tệp từ đầu vào người dùng — F02 là một trong các cảnh báo SAST được xác nhận (xem hình quét ở mục 4.1). Vì cảnh báo chỉ nêu vị trí, nhóm phân tích luồng xử lý và dùng **kiểm thử HTTP** để xác nhận việc vượt bộ lọc: kiểm thử `test/api/security/f01-f02.test.ts` gửi `GET /ftp/package.json.bak%2500.md` và yêu cầu phản hồi 403; trên mã chưa sửa, ca này báo đỏ (@fig(f0102-red)). Demo `demos/tv2_f02_pathtraversal.py` cho thấy cùng payload đọc được nội dung tệp ở bản chưa vá (@fig(tv2)).

### Sau khi sửa

Từ chối hẳn tên tệp chứa null byte (`%00` dạng chuỗi hoặc ký tự NUL thực `\u0000`) **trước** bước kiểm tra loại và phục vụ, thay vì cắt bỏ rồi gửi:

```typescript
if (file && (file.includes('%00') || file.includes('\u0000'))) {
  res.status(403)
  next(new Error('File names cannot contain null bytes!'))
  return
}
```

Sau khi sửa, hai payload `...%2500.md` bị từ chối **403**, trong khi tải tệp hợp lệ (`legal.md`) vẫn trả về bình thường (@fig(tv2)); kiểm thử bảo mật khi đó xanh toàn bộ (@fig(f0102-green)).

!fig[tv2.png](Demo F02: trước vá payload null byte đọc được `package.json.bak` và `coupons_2013.md.bak`; sau vá trả 403, tệp `.md` hợp lệ vẫn tải được){width=15}

!fig[f0102-green.png](Kiểm thử bảo mật F01/F02 sau khi sửa: toàn bộ 9 ca đạt){width=15}

**Nguyên tắc/tiêu chuẩn đối chiếu:** GDPR Điều 5(1)(f), 32(1)(b) (bảo mật, toàn vẹn khi xử lý). *Tệp bị lộ ở đây là cấu hình và mã giảm giá, không phải dữ liệu thẻ, nên không viện dẫn PCI-DSS.* **Pha DevSecOps:** Code → Test. **Kiểm soát (Security as Code):** phát hiện bằng SAST ở pha Code, chặn tái diễn bằng kiểm thử bảo mật tự động ở pha Test.

## 5.3. F03 — Lộ endpoint /metrics không xác thực

### Trước khi sửa

Juice Shop mở sẵn `/metrics` (Prometheus) mà không yêu cầu đăng nhập, xuất ra các chỉ số như số người dùng, số đơn hàng và tổng số dư ví. Khi container publish thẳng cổng ứng dụng, **mọi chủ thể truy cập tới host** đều gọi được endpoint này và đọc số liệu vận hành — vi phạm nguyên tắc *giảm bề mặt tấn công và tối thiểu phơi bày*. Đây là một rủi ro thuộc khâu **triển khai/vận hành**.

**Phát hiện.** Demo `demos/tv3_f03_metrics.py` gọi `/metrics` từ host; trước khi sửa, endpoint trả về 200 kèm hàng trăm dòng số liệu (@fig(tv3)).

### Sau khi sửa

Hướng xử lý là bỏ cổng host của backend và chỉ để reverse proxy mở cổng loopback; tại proxy, `/metrics` bị chặn và tốc độ đăng nhập bị giới hạn:

```nginx
location = /metrics { return 404; }
location = /rest/user/login { limit_req zone=login burst=5 nodelay; limit_req_status 429; proxy_pass http://juice-shop:3000; }
```

```yaml
juice-shop:
  networks: [backend]            # không còn khóa ports -> không truy cập trực tiếp từ host
networks:
  backend: { internal: true }
```

Sau khi sửa, `/metrics` đi qua proxy trả về 404 và cổng backend cũ bị từ chối kết nối **từ host**. Đây là chặn ở lối vào từ bên ngoài chứ không phải khóa tuyệt đối: trong mạng internal, hệ thống giám sát vẫn đọc được metrics đúng mục đích (@fig(tv3)).

!fig[tv3.png](Demo F03: /metrics lộ khi truy cập trực tiếp, bị chặn sau khi sửa){width=15}

**Nguyên tắc/tiêu chuẩn đối chiếu:** GDPR Điều 25(2), 32(1)(b). **Pha DevSecOps:** Deploy → Operate. **Kiểm soát (Policy as Code):** luật `compose.rego` chặn mọi cấu hình để backend mở cổng host (mục 4).

## 5.4. F04 — Sai cấu hình an toàn của container

Khác ba lỗi trên, F04 **không phải lỗi của image Juice Shop gốc** (image distroless gốc đã chạy non-root và đạt bộ luật). Đây là một **fixture cấu hình sai chủ động dựng** (`Dockerfile.vulnerable`) để kiểm tra *năng lực phát hiện* của bộ policy, sử dụng cả đầu vào "xấu" (chứng minh luật bắt được) và đầu vào "tốt" (chứng minh luật không báo nhầm).

### Trước khi sửa

Một image đóng gói Juice Shop có thể vi phạm chính sách an toàn tối thiểu mà vẫn lọt qua nếu kiểm tra đặt sai chỗ. `Dockerfile.vulnerable` dưới đây minh họa bốn vi phạm như vậy:

```dockerfile
FROM node:22-alpine
COPY . .
ENV API_TOKEN=supersecret123  # nhúng bí mật vào image (lộ qua docker history)
EXPOSE 3000 22 3306           # khai báo cổng 22 (SSH), 3306 (DB)
CMD ["npm", "start"]           # không USER (chạy root), không nhãn nguồn gốc
```

Những cách kiểm tra sơ sài dễ bị qua mặt. Kiểm tra kiểu "có lệnh `USER`" sẽ bỏ sót Dockerfile nhiều stage, vì `USER` ở stage builder không áp dụng cho image chạy thật. Kiểm tra `EXPOSE` chỉ đánh giá quy ước khai báo image, không phản ánh phơi nhiễm mạng thực tế (phải kiểm tại runtime). Nói chung, metadata tự khai trong image không thay cho bằng chứng thực thi.

**Rủi ro nếu để nguyên, không vá.** Mỗi vi phạm kéo theo một rủi ro an toàn cụ thể:

- **Chạy bằng root (LEAST-PRIVILEGE):** nếu về sau *giả định* tồn tại thêm một lỗ hổng **thực thi mã (RCE)** trong khi tiến trình chạy bằng root *bên trong* container, thiệt hại sẽ lớn hơn nhiều: kẻ tấn công dễ ghi đè file hệ thống, cài thêm công cụ, và nếu ghép thêm một lỗ hổng nhân hệ điều hành thì có thể **thoát container và leo thang đặc quyền** lên máy chủ. Lưu ý thực nghiệm F01 chỉ chứng minh **vượt xác thực**, chưa phải RCE; chạy non-root (UID 65532) là biện pháp *phòng thủ theo chiều sâu*, khoanh vùng thiệt hại cho những lỗ hổng giả định khác.
- **Khai báo cổng quản trị/CSDL (ATTACK-SURFACE):** `EXPOSE 22`/`3306` **tự nó không mở** cổng hay khởi động dịch vụ (EXPOSE chỉ mang tính tài liệu), nhưng là **tín hiệu** rằng image dự kiến chạy các dịch vụ này và thường đi kèm publish cổng khi vận hành. Luật chặn khai báo này để giữ *quy ước* image tối giản, hướng người viết Dockerfile không mang theo cổng nhạy cảm; còn phơi nhiễm **thực tế** phải kiểm bằng cấu hình runtime (cổng lắng nghe, publish, network policy), không suy ra từ EXPOSE.
- **Rủi ro chuỗi cung ứng (SUPPLY-CHAIN):** nếu thiếu nhãn nguồn gốc `org.opencontainers.image.source`/`revision`, khi có sự cố sẽ **khó truy vết image bắt nguồn từ commit nào** để điều tra hay thu hồi (đây là *metadata nguồn gốc tự khai*, hỗ trợ truy vết; **chưa đủ để kết luận đạt mức SLSA** — SLSA yêu cầu provenance được *sinh tự động*, mô tả cách build và được phân phối/kiểm chứng). Thêm vào đó, dùng `:latest` hoặc chưa ghim digest khiến image có thể **bị đổi âm thầm** giữa các lần build, làm bản chạy thật khác bản đã kiểm thử; còn lệnh `ADD` thì có thể kéo nội dung từ xa ngoài kiểm soát. Ghim digest cố định tham chiếu image, nhãn nguồn gốc hỗ trợ truy vết, COPY tránh kéo nội dung ngoài kiểm soát; đây là điều kiện cần cho build tái lập, chưa đủ nếu dependency và đầu vào build còn biến đổi.
- **Bí mật nhúng trong image (SECRET-IN-IMAGE):** đặt mật khẩu hay token trong `ENV`/`ARG` khiến bí mật **bị bake vào layer của ảnh**, và bất kỳ ai `docker pull` rồi chạy `docker history` đều đọc được, kể cả khi dòng đó đã bị xóa ở layer sau. Cách đúng là dùng *build secret* hoặc nạp biến môi trường lúc chạy. (Đây là **luật do nhóm bổ sung**, không có trong bản mẫu của lab.)

### Sau khi sửa

Việc xử lý gồm **hai phần tách bạch**: (1) **sửa chính file triển khai** cho đúng cấu hình an toàn, và (2) **viết chính sách kiểm tra tự động** để chống tái diễn. Conftest đánh giá cấu hình theo luật Rego, trả PASS/FAIL kèm lý do và mã thoát tương ứng; việc sửa cấu hình được thực hiện riêng trong Dockerfile.

**(1) Sửa file Dockerfile triển khai.** So với bản lỗi, bản vá (`report/fixtures/Dockerfile.remediated`) khắc phục đúng từng vi phạm tương ứng:

```dockerfile
FROM node:22-alpine
# THÊM nhãn nguồn gốc OCI  -> đạt SUPPLY-CHAIN (provenance)
LABEL org.opencontainers.image.source="https://github.com/juice-shop/juice-shop" \
      org.opencontainers.image.revision="${VCS_REF}"
RUN addgroup -S -g 10001 juicers && adduser -S -u 10001 -G juicers juicers
COPY --chown=10001:0 . .
USER 10001:10001          # THÊM USER non-root       -> đạt LEAST-PRIVILEGE
EXPOSE 3000               # BỎ cổng 22 và 3306        -> đạt ATTACK-SURFACE
CMD ["npm", "start"]
```

Cụ thể, bản vá thêm lệnh `USER` để chạy non-root, loại hai cổng quản trị/CSDL khỏi `EXPOSE`, bổ sung nhãn nguồn gốc OCI và **không đặt bí mật trong `ENV`/`ARG`** (dùng *build secret* hoặc nạp biến môi trường lúc chạy). Image triển khai thực tế của nhóm (`deploy/Dockerfile.hotfix`) lẫn Dockerfile gốc của Juice Shop đều đã thỏa những yêu cầu này.

**(2) Viết chính sách thành mã (Policy as Code).** Bộ luật Rego (`policy/docker_security.rego`) đặt mỗi luật đúng điểm thực thi để chặn các kiểu lách đã biết (vd `USER` ở stage builder không tính cho stage cuối; UID root kèm group như `0:1000`). Bộ luật có 13 ca kiểm thử, tất cả đạt (`conftest verify` 19/19). Mã nguồn đầy đủ ở **Phụ lục A**.

Các luật và tiêu chuẩn đối chiếu:

Table: Luật kiểm tra cấu hình container — luật yêu cầu gì và dựa trên chuẩn nào
| Luật | Luật yêu cầu gì (chặn khi vi phạm) | Tiêu chuẩn (ý nghĩa xem Phụ lục C) |
|---|---|---|
| LEAST-PRIVILEGE | Stage cuối **phải** có `USER` không phải root (bắt buộc, `deny`; tách UID trước dấu `:`); khuyến nghị UID số (`warn` nếu không) | CIS Docker 4.1; PCI-DSS 2.2; NIST SP 800-190 |
| ATTACK-SURFACE | **Không** được `EXPOSE` cổng quản trị/CSDL (22/23/3306/5432) | CIS Docker 5.8; NIST SP 800-190 |
| SUPPLY-CHAIN | **Phải** có nhãn nguồn gốc OCI; **không** dùng `:latest`/`ADD`; nên ghim digest | OCI image-spec; CIS Docker Benchmark §4; NIST SSDF (SLSA: *tham chiếu*, chưa đánh giá đạt) |
| SECRET-IN-IMAGE *(bổ sung)* | **Không** đặt secret/credential trong `ENV`/`ARG` | CIS Docker 4.10; PCI-DSS 8.2.1; GDPR Đ.32 |

Lệnh `conftest verify` chạy toàn bộ chính sách đạt **19/19** ca kiểm thử (13 ca cho chính sách Dockerfile của F04 và 6 ca cho chính sách compose của F03). Kết quả cho thấy `Dockerfile.vulnerable` bị chặn bởi 4 nhóm luật (LEAST-PRIVILEGE, ATTACK-SURFACE, SUPPLY-CHAIN, SECRET-IN-IMAGE), bản vá thì đạt, và Dockerfile gốc distroless của Juice Shop cũng **đạt bộ luật** (@fig(tv4)).

!fig[tv4.png](Demo F04: Dockerfile.vulnerable bị chặn bốn nhóm luật, bản vá và Dockerfile gốc đạt chính sách){width=15}

**Nguyên tắc/tiêu chuẩn đối chiếu:** GDPR Điều 25(1), 32(1)(d); CIS Docker Benchmark 4.1. **Pha DevSecOps:** Build → Release. **Kiểm soát (Policy as Code):** bộ luật Rego chạy như một cổng kiểm tra trong pipeline.

# 6. Kết luận

Báo cáo minh họa quy trình **phát hiện – sửa – kiểm chứng** cho hai lỗi mã nguồn (F01 SQL injection ở đăng nhập, F02 Poison Null Byte làm lộ tệp sao lưu), một tình huống phơi nhiễm endpoint giám sát (F03) và một tình huống cấu hình container sai **chủ động dựng** để kiểm tra bộ policy (F04). Toàn bộ được thể hiện dưới dạng Security as Code và Policy as Code trong một chuỗi kiểm soát DevSecOps chạy được, kèm log gốc và mã bằng chứng (mục 4.2).

Chuỗi kiểm soát trải khắp vòng đời — Code/Test (SAST + kiểm thử động), Build/Deploy (Policy as Code), Release (quét image Trivy/Dockle) đến Operate (Compliance as Code + giám sát Prometheus/Grafana). Phần đóng góp của nhóm — trong phạm vi bốn tình huống — gồm: bản vá F01/F02 kèm kiểm thử hồi quy; reverse proxy và giới hạn tốc độ cho F03; bộ luật Rego (Dockerfile + compose, 19 unit test) cho F04; quét image bằng **Trivy (CVE/SCA)** và **Dockle (CIS)** ở pha Release; và **giám sát vận hành bằng Prometheus/Grafana kèm cảnh báo** fire thật ở pha Operate. Kho mã Juice Shop gốc **đã có** CI/CD, CodeQL và tạo SBOM; báo cáo không khẳng định dự án gốc thiếu tự động hóa bảo mật, đóng góp ở đây là các kiểm soát **bổ sung, hướng dữ liệu cá nhân**.

Các giới hạn về phạm vi thực nghiệm và hướng mở rộng được trình bày trong tài liệu đi kèm *Giới hạn và hướng mở rộng* (`report/GIOI_HAN_VA_HUONG_MO_RONG.md`).

# 7. Tài liệu tham khảo

- OWASP Juice Shop v20.2.0 — https://owasp.org/www-project-juice-shop/ (truy cập 10/2026).
- GDPR, Regulation (EU) 2016/679, Điều 5, 25, 32.
- PCI-DSS v3.2.1 (đối chiếu lịch sử — đã nghỉ 31/3/2024; bản hiện hành v4.0.1), Yêu cầu 2.2, 3.4, 8.2.1 — pcisecuritystandards.org.
- CIS Docker Benchmark (§4 Container Images, §5 Runtime); OWASP Top 10 2021; NIST SP 800-190; NIST SSDF (SP 800-218); OCI image-spec; SLSA v1.x (slsa.dev).
- Công cụ (phiên bản dùng trong thực nghiệm): Semgrep 1.180.0, Gitleaks v8.30.1, Conftest/OPA v0.71.1, node:test + Supertest, Trivy 0.76.1, Dockle 0.4.15, Prometheus 3.15.1, Grafana 13.3.0.
- Phương pháp luận tham khảo: *Security as Code with OWASP Juice Shop & Docker*; *Policy as Code with Conftest*.

# Phụ lục A — Mã nguồn chính sách Dockerfile (docker_security.rego)

!include[policy/docker_security.rego]

# Phụ lục B — Mã nguồn chính sách docker-compose (compose.rego)

!include[policy/compose.rego]

# Phụ lục C — Giải thích tiêu chuẩn và điều khoản tham chiếu

Bảng tra ý nghĩa (**yêu cầu gì**) của mọi tiêu chuẩn/điều khoản được trích trong báo cáo. Phần thân chỉ ghi mã; ý nghĩa tra tại đây.

Table: Tra cứu — mỗi tiêu chuẩn/điều khoản tham chiếu yêu cầu gì
| Điều khoản | Yêu cầu / ý nghĩa tóm gọn |
|---|---|
| GDPR Điều 5(1)(f) | Nguyên tắc *toàn vẹn & bảo mật*: xử lý dữ liệu một cách an toàn |
| GDPR Điều 25 | Bảo vệ dữ liệu *từ thiết kế* (khoản 1) và *theo mặc định* (khoản 2) |
| GDPR Điều 32 | Biện pháp kỹ thuật & tổ chức bảo đảm an toàn khi xử lý — (1)(b) bí mật/toàn vẹn, (1)(d) kiểm thử & đánh giá định kỳ |
| OWASP A03:2021 / CWE-89 | *Injection* — tiêm nhiễm dữ liệu vào câu lệnh (SQL injection) |
| OWASP A01:2021 / CWE-158 | *Broken Access Control* — xử lý sai null byte (`%00`) làm vượt kiểm tra loại tệp (F02) |
| CWE-180 | Kiểm tra đầu vào *trước khi* chuẩn hóa — tên được kiểm tra khác tên thực sự dùng |
| PCI-DSS 2.2 | Cấu hình tham số an toàn hệ thống, chạy với đặc quyền tối thiểu |
| PCI-DSS 3.4 | Làm số thẻ (PAN) không đọc được ở mọi nơi lưu trữ |
| PCI-DSS 8.2.1 | Không lưu thông tin xác thực (credential) ở dạng đọc được |
| CIS Docker 4.1 | Chạy container bằng user riêng, **không phải root** |
| CIS Docker 4.9 | Dùng `COPY` thay cho `ADD` (tránh kéo nội dung từ xa ngoài kiểm soát) |
| CIS Docker 4.10 | Không lưu bí mật trong Dockerfile |
| CIS Docker 5.3 | Loại bỏ Linux capabilities không cần (`cap_drop: ALL`) |
| CIS Docker 5.4 | Không chạy container ở chế độ `privileged` |
| CIS Docker 5.8 | Chỉ mở đúng cổng cần thiết (không mở cổng quản trị/CSDL) |
| CIS Docker 5.12 | Gắn hệ thống tệp gốc ở chế độ chỉ đọc (`read_only`) |
| OCI image-spec | Chuẩn định dạng ảnh container + nhãn metadata nguồn gốc |
| SLSA | Khung toàn vẹn chuỗi cung ứng. Mức Build L1 yêu cầu provenance được *sinh tự động* và phân phối; nhãn OCI tự khai trong báo cáo **chưa đạt** L1, chỉ dùng để tham chiếu |
| NIST SP 800-190 | Hướng dẫn an toàn cho container |

