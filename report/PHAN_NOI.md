# PHẦN NÓI — Kịch bản thuyết trình báo cáo

**Đề tài:** Đánh giá an toàn và xử lý lỗ hổng OWASP Juice Shop v20.2.0
**Học phần:** DevOps và DevSecOps (SEC4349) — Khoa An toàn thông tin, PTIT

Tổng thời lượng gợi ý: **17–20 phút** + hỏi đáp. Mỗi người nói phần lỗi của mình, kèm chạy demo.
Nguyên tắc: *không đọc nguyên bảng trên slide* — nói ý chính, chỉ vào hình/demo khi tới đoạn tương ứng.

**Thứ tự nói:** Mở đầu → Giới thiệu ứng dụng (Thắng) → Môi trường, công cụ, chính sách (Thúy) → F01 (Thắng) → F02 (Thúy) → F03 (Quốc Anh) → F04 + Tổng hợp + Kết luận (Vũ).

---

## MỞ ĐẦU — Nguyễn Toàn Thắng (≈1 phút)

> Em kính chào thầy/cô và các bạn. Nhóm em gồm 4 thành viên, hôm nay trình bày báo cáo đánh giá an toàn ứng dụng **OWASP Juice Shop phiên bản 20.2.0** theo hướng **bảo vệ dữ liệu người dùng**.
>
> Juice Shop là ứng dụng thương mại điện tử do OWASP phát hành, **cố ý chứa lỗ hổng để huấn luyện** an toàn ứng dụng — nên mục tiêu của nhóm là **minh họa quy trình phát hiện và xử lý lỗi**, chứ không phải đánh giá dự án gốc.
>
> Nhóm chọn **4 lỗi**: hai lỗi thuộc **mã nguồn** và hai lỗi thuộc **triển khai/vận hành**. Mỗi thành viên phụ trách một lỗi, trình bày theo mạch **trước khi sửa → sau khi sửa**, gồm: cách phát hiện, cách xử lý, chính sách bị vi phạm, pha DevSecOps và đoạn mã demo. Trước khi vào từng lỗi, em xin giới thiệu về ứng dụng và các thành phần của nó.

*(Cue: mở slide phân công.)*

---

## GIỚI THIỆU ỨNG DỤNG VÀ THÀNH PHẦN — Nguyễn Toàn Thắng (≈2 phút)

> Juice Shop là một **Single Page Application** — tức toàn bộ giao diện chạy trên trình duyệt và gọi về máy chủ qua **REST API**. Em xin điểm qua các thành phần chính, vì mỗi thành phần đều liên quan tới một trong bốn lỗi:
>
> - **Giao diện** viết bằng **Angular** — chỉ hiển thị và gọi API, không giữ logic bảo mật; nên mọi kiểm soát phải nằm ở máy chủ.
> - **Máy chủ ứng dụng** là **Node.js + Express** — xử lý REST API và nghiệp vụ. Đây là nơi phát sinh **F01 và F02**.
> - **Truy xuất dữ liệu** qua **ORM Sequelize** trên cơ sở dữ liệu **SQLite** — lưu bảng Users, Baskets, Cards. Cách *viết câu truy vấn* ở đây chính là gốc của F01.
> - **Xác thực phiên** bằng **JWT** — sau khi đăng nhập, máy chủ cấp một token để nhận diện người dùng ở các lần gọi sau.
> - **Giám sát** bằng thư viện prom-client, mở endpoint **`/metrics`** theo chuẩn Prometheus — liên quan tới **F03**.
> - **Đóng gói** bằng **Docker image distroless** — liên quan tới **F04**.
>
> Về nghiệp vụ, nhóm tập trung hai luồng có dữ liệu nhạy cảm. Thứ nhất là **đăng ký và đăng nhập**: người dùng đăng nhập qua `POST /rest/user/login`, máy chủ truy vấn bảng Users, nếu khớp thì cấp JWT. **Ranh giới tin cậy** quan trọng ở đây: email do client gửi lên **đi thẳng vào câu lệnh SQL** — đó là gốc của F01. Thứ hai là **giỏ hàng**: sau khi đăng nhập, người dùng gọi `GET /rest/basket/:id` để xem giỏ; nếu máy chủ không ràng buộc *giỏ này của ai* thì sinh ra F02.
>
> Từ đó, **dữ liệu nhóm cần bảo vệ** gồm: email và hồ sơ, mật khẩu, token phiên, giỏ hàng — đối chiếu theo **GDPR** Điều 5, 25, 32; và thẻ thanh toán theo **PCI-DSS**. Về cách chứng minh, nhóm chạy cùng một kịch bản trên **hai môi trường**: cổng **3100** là container chạy image gốc — *trước khi sửa*; cổng **3102** là bản đã vá, truy cập qua reverse proxy — *sau khi sửa*. Tiếp theo, mời bạn Thúy giới thiệu môi trường và bộ công cụ.

*(Cue: slide thành phần ứng dụng + bảng dữ liệu cần bảo vệ.)*

---

## MÔI TRƯỜNG, CÔNG CỤ VÀ CHÍNH SÁCH — Phạm Thị Minh Thúy (≈2 phút)

> Em cảm ơn bạn Thắng. Em xin nói về **môi trường triển khai** và **bộ công cụ** nhóm dùng.
>
> Ứng dụng chạy bằng **Docker** trên Windows WSL2, triển khai bằng `docker-compose`. Nhóm áp dụng **an toàn tối thiểu** theo CIS Docker Benchmark: **chỉ reverse proxy được mở cổng** và chỉ trên loopback 127.0.0.1, backend đưa vào **mạng internal**; container **không chạy root**; drop toàn bộ capability và bật `no-new-privileges`; **ghim image theo digest**; và Nginx **chặn `/metrics`, giới hạn 5 lần đăng nhập mỗi phút**.
>
> Về **công cụ**, nhóm dùng sáu nhóm, mỗi cái một vai trò rõ ràng — và em muốn nhấn mạnh **không có cái nào trùng vai trò**:
>
> - **Docker và Docker Compose** — nền tảng chạy container và dựng hai môi trường trước/sau.
> - **Nginx** — reverse proxy, dùng để chặn `/metrics` và giới hạn tốc độ đăng nhập (F03).
> - **Semgrep** — công cụ **SAST**, tức phân tích **tĩnh**: *đọc mã mà không chạy*, chỉ ra đúng dòng lỗi F01, F02.
> - **Gitleaks** — quét **secret**, tìm khóa hoặc mật khẩu bị lộ trong mã.
> - **node:test với Supertest** — kiểm thử **động**: *chạy ứng dụng thật*, gửi request để tái hiện lỗi trước khi vá và kiểm chứng sau khi vá. Khác Semgrep ở chỗ Semgrep **tìm ra** chỗ nghi ngờ, còn node:test **chứng minh** lỗi có thật và đã hết.
> - **Conftest/OPA** với ngôn ngữ **Rego** — **Policy as Code**: viết chính sách an toàn thành mã để kiểm tra Dockerfile và cấu hình triển khai (F03, F04).
>
> Cuối cùng là **chính sách và tiêu chuẩn** nhóm đối chiếu — đều là chuẩn phổ biến, **không phải quy ước tự đặt**: **GDPR** làm khung bảo vệ dữ liệu cá nhân; **PCI-DSS** cho dữ liệu thẻ; **OWASP Top 10 và CWE** để phân loại lỗi — F01 là A03 Injection, F02 là A01 Broken Access Control; **CIS Docker Benchmark** cho cấu hình container; và **SLSA, OCI image-spec** cho nguồn gốc image ở F04. Sau đây mời bạn Thắng trình bày lỗi đầu tiên.

*(Cue: slide bảng công cụ + hình `hardening.png`.)*

---

## F01 — SQL injection tại đăng nhập — Nguyễn Toàn Thắng (≈2,5 phút)

> Em cảm ơn bạn Thúy. Lỗi thứ nhất là **SQL injection tại chức năng đăng nhập**, thuộc nhóm lỗi mã nguồn, mã CWE-89, OWASP A03:2021 Injection.
>
> **Trước khi sửa:** route `login.ts` **ghép thẳng** email người dùng nhập vào câu lệnh SQL. Vì vậy, nếu em nhập email là `' OR 1=1--` thì mệnh đề WHERE luôn đúng, còn phần kiểm tra mật khẩu bị biến thành chú thích. Kết quả: máy chủ cấp token của tài khoản đầu tiên — thường là **quản trị** — mà **không cần mật khẩu**.
>
> **Cách phát hiện:** nhóm dùng hai lớp. Thứ nhất, **Semgrep** — công cụ phân tích tĩnh, *đọc mã mà không chạy* — chỉ đúng dòng truy vấn nhiễm dữ liệu. Thứ hai, **kiểm thử bảo mật** bằng node:test: gửi payload tấn công kèm mật khẩu sai và yêu cầu phải nhận mã 401; trên mã chưa sửa, các ca này **đỏ**.
>
> *(Cue: chạy `python report/v3/demos/tv1_f01_sqli.py`)* — Như thầy/cô thấy, ở cột *trước vá*, cả ba payload đều được cấp token; ở cột *sau vá*, tất cả đều bị từ chối 401, còn đăng nhập hợp lệ vẫn hoạt động bình thường.
>
> **Cách xử lý:** chuyển sang **truy vấn tham số** — dùng bind parameter. Câu lệnh được biên dịch trước, giá trị email gửi riêng, nên mọi ký tự SQL trong email chỉ còn là **dữ liệu thuần**, không thể đổi cấu trúc câu lệnh. Sau khi sửa, kiểm thử bảo mật **xanh toàn bộ**.
>
> **Chính sách vi phạm:** GDPR Điều 32(1)(b) — bảo mật khi xử lý dữ liệu. **Pha DevSecOps:** phát hiện ở pha **Code** bằng SAST, chặn tái diễn ở pha **Test**. Em xin chuyển phần cho bạn Thúy.

---

## F02 — IDOR khi đọc giỏ hàng — Phạm Thị Minh Thúy (≈2 phút)

> Em cảm ơn bạn Thắng. Lỗi thứ hai là **IDOR — tham chiếu đối tượng thiếu kiểm soát truy cập** — khi đọc giỏ hàng, mã CWE-639, OWASP A01:2021 Broken Access Control.
>
> **Trước khi sửa:** route `basket.ts` tìm giỏ hàng **chỉ theo mã id trên URL**. Middleware chỉ kiểm tra token có hợp lệ hay không, **không kiểm tra giỏ đó có thuộc về người gọi**. Vì vậy, một người dùng chỉ cần đổi `/rest/basket/8` thành `/rest/basket/9` là **đọc được giỏ hàng của người khác** — mà giỏ hàng phản ánh thói quen mua sắm, là dữ liệu cá nhân.
>
> **Cách phát hiện:** nhóm tạo hai tài khoản A và B, rồi dùng token của A để đọc giỏ của B.
>
> *(Cue: chạy `python report/v3/demos/tv2_f02_idor.py`)* — Trước vá, A đọc được giỏ của B, trả về mã 200 kèm dữ liệu. Sau vá, hành vi đó nhận **404**, còn A đọc giỏ của chính mình vẫn 200.
>
> **Cách xử lý:** **ràng buộc chủ sở hữu ngay trong truy vấn** — thêm điều kiện `UserId` bằng id của phiên đang đăng nhập, và **danh tính lấy từ phiên do máy chủ cấp**, không lấy từ dữ liệu client. Đồng thời kiểm tra id hợp lệ. Nếu không đúng chủ, trả 404.
>
> **Chính sách vi phạm:** GDPR Điều 5(1)(f) — tính toàn vẹn và bảo mật, và Điều 25(2) — bảo vệ dữ liệu ngay từ thiết kế. **Pha DevSecOps:** phát hiện ở pha **Test** bằng kiểm thử phân quyền, giữ trong pipeline để chống tái diễn. Em xin chuyển phần cho bạn Quốc Anh.

---

## F03 — Lộ endpoint /metrics không xác thực — Đỗ Đức Quốc Anh (≈2 phút)

> Em cảm ơn bạn Thúy. Lỗi thứ ba là **lộ endpoint `/metrics` không cần xác thực** — đây là lỗi **triển khai/vận hành**, không phải lỗi mã nguồn.
>
> **Trước khi sửa:** Juice Shop mặc định mở `/metrics` theo chuẩn Prometheus **mà không cần đăng nhập**. Endpoint này lộ số người dùng, số đơn hàng, tổng số dư ví — là thông tin nhạy cảm về hệ thống. Khi container publish thẳng cổng ứng dụng ra máy chủ, **bất kỳ ai cũng gọi được** từ bên ngoài.
>
> *(Cue: chạy `python report/v3/demos/tv3_f03_metrics.py`)* — Trước vá, gọi `/metrics` ở cổng 3100 trả về 200 với hàng trăm dòng số liệu. Sau vá, ba điểm cần lưu ý: một là `/metrics` qua proxy trả **404**; hai là cổng backend cũ **bị từ chối kết nối**; ba là hệ thống **giám sát nội bộ vẫn đọc được** metrics qua mạng internal — tức là mình **chặn được bên ngoài mà không mất chức năng giám sát**.
>
> **Cách xử lý:** bỏ cổng host của backend, đưa backend vào **mạng internal**; chỉ **reverse proxy Nginx** được mở cổng, và chỉ trên loopback. Nginx **chặn `/metrics` trả 404** và **giới hạn tốc độ đăng nhập** 5 lần mỗi phút để chống dò mật khẩu.
>
> **Chính sách vi phạm:** GDPR Điều 25(2) và 32(1)(b). **Pha DevSecOps:** lỗi ở pha **Deploy/Operate**; và nhóm viết luật `compose.rego` để **chặn mọi cấu hình cho backend mở cổng** — phần này bạn Vũ sẽ nói kỹ hơn ở Policy as Code. Em xin chuyển phần cho bạn Vũ.

---

## F04 — Sai cấu hình an toàn của container — Hồ Anh Vũ (≈2,5 phút)

> Em cảm ơn bạn Quốc Anh. Lỗi thứ tư là **sai cấu hình an toàn của container**, thuộc pha **Build/Release**, và nhóm xử lý bằng **Policy as Code**.
>
> **Vấn đề:** cách đóng gói image có thể vi phạm chính sách an toàn tối thiểu mà vẫn **lọt** nếu kiểm tra sai chỗ. Nhóm em làm một `Dockerfile.vulnerable` minh họa **bốn vi phạm**: một là **nhúng bí mật** (`ENV API_TOKEN=...`) vào image; hai là **không có lệnh USER** nên container chạy bằng **root**; ba là **EXPOSE cổng 22 và 3306** — tức SSH và cơ sở dữ liệu; bốn là **thiếu nhãn nguồn gốc**.
>
> **Nếu để nguyên, không vá thì rủi ro gì?** Em xin phân tích từng cái:
> - **Chạy root** là nặng nhất: nếu ứng dụng bị chiếm quyền qua một lỗ hổng khác — ví dụ chính F01 — thì kẻ tấn công có ngay quyền root *trong* container, dễ ghi đè file, cài công cụ, và có thể **thoát container, leo thang** lên máy chủ. Chạy non-root giới hạn thiệt hại.
> - **Nhúng bí mật vào image (SECRET-IN-IMAGE)**: mật khẩu/token đặt trong ENV/ARG bị **bake vào layer**, ai `docker pull` rồi `docker history` đều đọc được — kể cả khi đã xóa ở layer sau. Đây là **luật riêng nhóm tự thêm**, không có trong bản mẫu của lab.
> - **Mở cổng 22/3306** làm **tăng bề mặt tấn công**, tạo đường dò quét và tấn công vào SSH, cơ sở dữ liệu — nơi chứa dữ liệu người dùng.
> - **Rủi ro chuỗi cung ứng (SUPPLY-CHAIN)**: thiếu nhãn nguồn gốc thì khi sự cố xảy ra **không truy vết được image từ commit nào** để điều tra, thu hồi (đây là provenance *khai báo* theo SLSA L1 — muốn chắc hơn thì ký attestation); thêm nữa, dùng `:latest` hoặc chưa ghim digest thì image có thể bị **đổi âm thầm** giữa các lần build.
>
> **Điểm cốt lõi:** các kiểm tra **ngây thơ dễ bị qua mặt** — ví dụ "có lệnh USER là đạt" sẽ bỏ sót Dockerfile nhiều stage; "EXPOSE không chứa cổng cấm" thì vô nghĩa vì EXPOSE chỉ là tài liệu; nhãn tự khai `mfa=true` thì ai cũng ghi được. Nên nhóm đặt **mỗi luật đúng điểm thực thi**: ví dụ luật LEAST-PRIVILEGE chỉ xét **USER ở stage cuối** và phải là **UID số**.
>
> **Cách xử lý có hai phần.** Thứ nhất là **sửa chính Dockerfile**: thêm lệnh `USER` chạy non-root, **bỏ cổng 22 và 3306**, và **thêm nhãn nguồn gốc OCI**. Thứ hai là **viết chính sách bằng Conftest/OPA**. Ở đây em xin nhấn mạnh hai điều hay bị hỏi: một là **Conftest không có luật sẵn** — nó là bộ máy chính sách trống, tự nó không quét ra gì; *cách phát hiện* chính là bộ luật Rego nhóm viết, kèm unit test chứng minh luật bắt đúng (mã nguồn đầy đủ ở Phụ lục A). Hai là **Conftest không tự sửa file** — nó chỉ *kiểm tra và chặn phát hành* nếu còn vi phạm; việc sửa Dockerfile là do mình làm. Đó đúng là tinh thần Policy as Code: tổ chức tự mã hóa chính sách của mình. Về phân định nguồn: `docker_security.rego` **kế thừa** các luật cốt lõi từ Appendix A.1 của lab, nhóm **điều chỉnh** (bỏ HEALTHCHECK, gộp provenance vào chuỗi cung ứng) và **tự thêm luật SECRET-IN-IMAGE**; còn chính sách compose (F03) là **nhóm tự viết** vì lab dùng Kubernetes chứ không dùng docker-compose.
>
> *(Cue: chạy `python report/v3/demos/tv4_f04_policy.py`)* — Bộ chính sách đạt **17/17 ca kiểm thử**. `Dockerfile.vulnerable` bị chặn **4 nhóm luật** (LEAST-PRIVILEGE, ATTACK-SURFACE, SUPPLY-CHAIN, SECRET-IN-IMAGE); bản vá và image hotfix **đạt**; và đáng chú ý là **Dockerfile gốc của Juice Shop đạt toàn bộ chính sách an toàn** — nghĩa là chính sách của nhóm vừa đủ chặt để bắt cấu hình sai, vừa không báo nhầm image thật.
>
> **Chính sách vi phạm:** GDPR Điều 25(1), 32(1)(d); CIS Docker Benchmark 4.1. Các luật đối chiếu CIS Docker, PCI-DSS, OCI image-spec và SLSA.

---

## TỔNG HỢP — Policy as Code & Security as Code — Hồ Anh Vũ (≈1,5 phút)

> Nhìn tổng thể, toàn bộ việc phát hiện và chống tái diễn bốn lỗi đều được **viết thành mã** và **chạy lặp lại được**, đúng tinh thần DevSecOps, chia hai nhóm:
>
> - **Security as Code:** quét secret bằng Gitleaks, phân tích tĩnh bằng Semgrep cho F01/F02, và kiểm thử bảo mật tự động — đỏ trước vá, xanh sau vá.
> - **Policy as Code:** luật Rego/Conftest cho Dockerfile của F04 và cho docker-compose của F03 — chặn cấu hình mở cổng backend hoặc chạy root, và kiểm tra lại container đang chạy bằng `docker inspect`.
>
> Các kiểm soát này ghép thành **chuỗi cổng (gate) trong CI**: cổng nào FAIL thì **chặn phát hành**. Và điểm nhóm muốn nhấn mạnh: **đoạn mã demo của mỗi thành viên áp dụng trực tiếp kỹ thuật trong tài liệu môn học** — shift-left và SAST, Test-Driven Security, giảm phơi nhiễm endpoint, và Policy as Code với Conftest.

---

## KẾT LUẬN — Hồ Anh Vũ (hoặc Nguyễn Toàn Thắng) (≈1 phút)

> Tóm lại, nhóm em đã xử lý **bốn lỗi**: hai lỗi mã nguồn là F01 SQL injection và F02 IDOR; hai lỗi triển khai là F03 lộ `/metrics` và F04 sai cấu hình container. Mỗi lỗi đều được **phát hiện bằng công cụ hoặc kiểm thử, xử lý, và kiểm chứng** theo mạch trước → sau, kèm đoạn mã demo chạy được.
>
> Những biện pháp này **không có sẵn trong Juice Shop gốc** — vốn cố ý để lỗ hổng, không có truy vấn tham số, không reverse proxy, không chính sách cấu hình container, không cổng kiểm soát trong CI. Đó chính là **phần giá trị mà nhóm bổ sung**.
>
> Phần trình bày của nhóm em đến đây là hết. Chúng em xin cảm ơn thầy/cô và các bạn, và sẵn sàng nhận câu hỏi.

---

## CÂU HỎI PHẢN BIỆN THƯỜNG GẶP — gợi ý trả lời

**1. Vì sao dùng cả Semgrep và node:test? Có trùng nhau không?**
> Không trùng. Semgrep là phân tích **tĩnh** — đọc mã, chỉ ra *dòng* khả nghi, rất nhanh, chạy được cả khi app chưa chạy. node:test là kiểm thử **động** — chạy app thật, *chứng minh* lỗi tồn tại trước khi vá (đỏ) và biến mất sau khi vá (xanh). Một cái **tìm ra**, một cái **kiểm chứng** — bổ sung cho nhau.

**2. Truy vấn tham số khác gì so với việc "escape" ký tự đặc biệt?**
> Escape là lọc thủ công, dễ sót trường hợp. Truy vấn tham số thì câu lệnh được **biên dịch trước**, dữ liệu gửi qua kênh riêng, nên dữ liệu **không bao giờ** được hiểu là mã — an toàn theo thiết kế, không phụ thuộc vào việc lọc đủ hay thiếu.

**3. F02 vì sao trả 404 chứ không phải 403?**
> Trả 404 để **không tiết lộ** là giỏ đó có tồn tại hay không. 403 "cấm" gián tiếp xác nhận tài nguyên tồn tại; 404 che luôn sự tồn tại, giảm rò rỉ thông tin.

**4. Chặn `/metrics` thì còn giám sát được không?**
> Vẫn được. Nhóm chỉ chặn **đường từ bên ngoài**; hệ thống giám sát nằm **trong mạng internal** vẫn đọc metrics bình thường — demo F03 cho thấy rõ điều này.

**5. EXPOSE chỉ là tài liệu, sao lại coi là lỗi?**
> Đúng là EXPOSE không tự mở cổng. Nhóm coi nó là **tín hiệu ý định** sai và kiểm tra ở tầng chính sách; còn việc mở cổng thật thì luật `compose.rego` của F03 chặn ở tầng triển khai. Hai luật bổ sung nhau.

**6. Vì sao đặt luật "USER ở stage cuối" thay vì "có USER là đạt"?**
> Vì Dockerfile nhiều stage: stage builder có thể có USER nhưng stage chạy thật thì không. Chỉ **stage cuối** mới tạo ra image chạy, nên luật phải xét đúng chỗ đó, và yêu cầu **UID số** để không bị qua mặt bằng tên.

**7. Các lỗi này có thật trong Juice Shop không, hay nhóm tự tạo?**
> Có thật. F01, F02 nằm trong `login.ts`, `basket.ts`; F03 là `/metrics` mở mặc định. F04 minh họa bằng `Dockerfile.vulnerable` để thể hiện chính sách, nhưng áp dụng kiểm tra lên cả Dockerfile gốc và container đang chạy thật.

**8. GDPR áp cho bài này nghĩa là sao?**
> Nhóm dùng GDPR làm **khung đối chiếu kỹ thuật** — Điều 5, 25, 32 — để chỉ ra mỗi lỗi vi phạm nguyên tắc bảo vệ dữ liệu nào. Đây là ánh xạ rủi ro kỹ thuật, **không phải kết luận pháp lý**.

**9. Conftest có tự sửa Dockerfile không? Vậy F04 "sửa" ở đâu?**
> Conftest **không tự sửa** — nó chỉ *kiểm tra*, trả PASS/FAIL, đóng vai trò **cổng gác trong CI**. Việc sửa là người phát triển sửa Dockerfile: **thêm `USER` non-root, bỏ cổng 22/3306, thêm nhãn nguồn gốc OCI** (xem `Dockerfile.remediated`). Conftest đảm bảo nếu còn vi phạm thì build **không được phát hành**. Hai việc tách bạch: *sửa file* là của người, *chặn tái diễn* là của chính sách.

**10. Conftest tự quét ra lỗi à, hay phải viết luật?**
> Conftest **không có luật sẵn** — khác Semgrep (có bộ luật) hay Gitleaks (có mẫu secret). Nó là **bộ máy chính sách tổng quát (OPA/Rego)**, chỉ kiểm tra đúng những luật mình viết. Nên *cách phát hiện* của F04 **chính là bộ luật Rego nhóm cung cấp** (kế thừa từ Appendix A.1 của lab + nhóm bổ sung luật riêng như SECRET-IN-IMAGE), kèm 11 unit test chứng minh luật bắt đúng và không bị qua mặt (xem Phụ lục A). Đây là điểm mạnh của Policy as Code: chính sách tường minh, version-control được, test được — không phụ thuộc "ý kiến" có sẵn của vendor.

**11. Vá F01 xong thì mật khẩu đã an toàn chưa?**
> Chưa hoàn toàn. F01 chỉ xử lý **vượt xác thực bằng injection**. Cùng dòng code đó vẫn băm mật khẩu bằng **MD5 không muối** (`lib/insecurity.ts:41`, CWE-327) — đây là lỗ hổng **lưu trữ** mật khẩu, nằm ngoài phạm vi F01, nhóm nêu rõ là *giới hạn còn lại* trong báo cáo. Hướng khắc phục thật là thay bằng **bcrypt/argon2 có muối**. (Trả lời thẳng điểm này cho thấy nhóm hiểu ranh giới của bản vá, không khoe quá.)

**12. Nói "cổng chặn phát hành" — mọi luật đều chặn à?**
> Không. Chỉ luật **`deny` (mức FAIL)** mới chặn phát hành; luật **`warn` (mức WARN)** chỉ **cảnh báo**, không chặn. Ví dụ trong `compose.rego`: mở cổng backend, bind ngoài loopback, privileged, mount docker.sock, secret nội tuyến là `deny` → chặn; còn `cap_drop`/`read_only` là `warn` → khuyến cáo. Hiện chuỗi cổng **chạy cục bộ** (xem `DEMO.md`), thiết kế để ghép vào CI.

---

## LƯU Ý KHI TRÌNH BÀY

- Khởi động môi trường trước khi lên: xem `DEMO.md` ở thư mục gốc (mục 1). Mở sẵn 2 terminal.
- Chạy thử cả 4 demo một lần trước buổi báo cáo để chắc chắn container đang chạy (3100 và 3102).
- Khi demo, **đọc kết quả theo cột trước vá / sau vá** — đó là bằng chứng mạnh nhất.
- Nếu máy không chạy được demo, dùng các hình trong báo cáo: `semgrep.png`, `f0102-red/green.png`, `tv1–tv4.png`.
- Giữ nhịp: mỗi người ~2 phút, tổng ~13–15 phút, chừa 3–5 phút hỏi đáp.
