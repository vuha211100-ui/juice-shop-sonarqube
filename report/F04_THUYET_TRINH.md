# F04 — Tài liệu thuyết trình: Sai cấu hình an toàn của container (Hồ Anh Vũ)

> Dựa trên `report/SLIDE_BaoCao_JuiceShop.pptx` (slide 13 bộ luật, slide 15 kết quả quét, **slide 20 F04**, **slide 27 phần việc thành viên 4/4**; slide riêng `report/slide/TV4_HoAnhVu_B26CHAT048.pptx`) và báo cáo `report/BaoCao_DevSecOps_JuiceShop_gon.docx` mục 5.4, Bảng 10, Phụ lục A.
> Mọi output trong tài liệu là **kết quả chạy thật** (Conftest v0.71.1) — có thể chạy lại bằng lệnh kèm theo.

Mục lục: 1. Thông điệp chính · 2. Kịch bản nói slide 20 · 3. Kịch bản nói slide 27 · 4. Rego cơ bản để hiểu code · 5. Giải thích từng dòng `docker_security.rego` · 6. Giải thích 13 ca kiểm thử · 7. `runtime.rego` và Dockle (3 lớp kiểm) · 8. Hậu quả an ninh của từng vi phạm · 9. Những gì bộ luật CHƯA bắt (đã chạy thử) · 10. Hướng mở rộng · 11. Câu hỏi phản biện · 12. Chất liệu "chém gió" · 13. Checklist trước giờ G · 14. Tổng hợp toàn bộ luật (Dockerfile + compose + runtime) + mapping luật → chuẩn (14.4)

---

## 1. Thông điệp chính (học thuộc 3 câu này)

1. **F04 không phải lỗi của Juice Shop gốc.** Image gốc (distroless, UID 65532) đạt bộ luật. Nhóm *chủ động dựng* `Dockerfile.vulnerable` — một **fixture** — để chứng minh bộ luật **bắt được cái sai** và **không báo nhầm cái đúng**.
2. **Luật đặt đúng điểm thực thi, không kiểm hình thức.** Ví dụ: không kiểm "có lệnh USER không" mà kiểm "USER ở **stage cuối** có phải root không, kể cả dạng `0:1000`".
3. **Policy as Code là một cổng tự động ở pha Build**: vi phạm → `exit 1` → pipeline dừng, không build/phát hành. Bộ luật tự có 13 ca kiểm thử, `conftest verify` đạt 19/19 (13 Dockerfile + 6 compose).

**Câu mở màn 30 giây (elevator pitch):**
"Một container chạy root, có mật khẩu nằm sẵn trong image và mở cổng SSH thì vẫn *chạy được bình thường* — không ai thấy lỗi cho tới khi bị tấn công. F04 của em biến các quy tắc an toàn container thành mã Rego, chạy tự động mỗi lần build: sai là chặn, ngay từ file Dockerfile, trước khi image tồn tại."

---

## 2. Kịch bản nói — Slide 20 (F04), ~4 phút kể cả demo

**[Mở đầu — chỉ vào ô F04 và các nhãn bên phải]**
"Em là Hồ Anh Vũ, phụ trách F04 — sai cấu hình an toàn của container. Đối chiếu CIS Docker Benchmark, NIST SP 800-190 và PCI-DSS; về GDPR là Điều 25(1) — bảo vệ từ khi thiết kế, và 32(1)(d) — kiểm thử định kỳ; nằm ở pha Build → Release."

**[Lỗi — chỉ ô LỖI]**
"Trước hết em nói rõ: image Juice Shop gốc **không sai**. Nó chạy distroless, user không phải root, và đạt bộ luật. Để chứng minh bộ luật thực sự bắt được lỗi, nhóm dựng một Dockerfile cố ý sai — `report/fixtures/Dockerfile.vulnerable`. Kỹ thuật này gọi là *fixture*: cho đầu vào xấu để thấy luật chặn, đầu vào tốt để thấy luật không chặn nhầm."

**[Trước khi sửa — chỉ từng dòng khung code]**
"Tệp lỗi có 4 nhóm vi phạm:
- `ENV API_TOKEN=supersecret123` — bí mật nằm thẳng trong image;
- không có `USER` — container chạy bằng root;
- `EXPOSE 3000 22 3306` — khai báo cổng SSH và MySQL;
- không có nhãn nguồn gốc OCI — không truy được image build từ commit nào."

**[Impact]**
"Hậu quả: chạy root thì nếu ứng dụng có lỗ hổng thực thi mã, kẻ tấn công có toàn quyền trong container và một lỗ hổng runtime như runc CVE-2019-5736 có thể đưa họ lên root của máy chủ. Bí mật trong ENV thì ai kéo được image về là đọc được bằng `docker history`, kể cả khi đã xóa ở layer sau. Cổng 22/3306 là dấu hiệu image chạy thêm dịch vụ nhạy cảm, và chỉ cần ai đó chạy `docker run -P` là các cổng này được publish ra host."

**[Phát hiện]**
"Conftest đọc Dockerfile thành dữ liệu JSON, rồi đối chiếu với bộ luật Rego `docker_security.rego`. Với tệp lỗi: **exit 1, 6 vi phạm thuộc 4 nhóm**. Bộ luật có 13 ca kiểm thử riêng, `conftest verify` đạt 19/19."

**[Sau khi sửa — chỉ khung xanh]**
"Bản vá: tạo user riêng UID 10001 và `USER 10001:10001`; chỉ `EXPOSE 3000`; thêm nhãn `org.opencontainers.image.source` và `.revision`; bỏ bí mật khỏi ENV — bí mật cần thì nạp lúc chạy hoặc dùng build secret."

**[Demo]** — gõ: `python report/demos/tv4_f04_policy.py`
Output thật và cách nói:

```
conftest verify -p policy  ->  19 tests, 19 passed, 0 warnings, 0 failures, 0 exceptions, 0 skipped

Dockerfile                                  Exit  Nhóm luật bị chặn                                               Kết luận
------------------------------------------  ----  --------------------------------------------------------------  --------------------
Dockerfile.vulnerable (6 vi phạm / 4 nhóm)  1     ATTACK-SURFACE, LEAST-PRIVILEGE, SECRET-IN-IMAGE, SUPPLY-CHAIN  đúng: gate chặn
Dockerfile.remediated (bản vá)              0     -                                                               đúng: đạt chính sách
Dockerfile gốc Juice Shop (distroless)      0     -                                                               đúng: đạt chính sách
hotfix image F01/F02                        0     -                                                               đúng: đạt chính sách
```

"Dòng đầu: bộ luật tự kiểm 19/19. Dòng thứ hai: tệp lỗi exit 1, bị chặn đủ 4 nhóm. Ba dòng sau: bản vá, Dockerfile gốc và Dockerfile của image đã vá đều exit 0. **Luật bắt đúng cái sai, không báo nhầm cái đúng.**"

> Nếu được hỏi về WARN: bản vá và Dockerfile gốc có 1–2 dòng `WARN ... not pinned by digest` — đây là *khuyến nghị*, không chặn (exit vẫn 0). Riêng `Dockerfile.hotfix` ghim digest nên sạch hoàn toàn: 10/10.

**[Chốt + chuyển]** "Luật Rego gác ở pha Build, nên cấu hình sai bị chặn trước khi image được tạo ra. Bốn tình huống được tổng hợp ở bảng kết quả hợp nhất."

---

## 3. Kịch bản nói — Slide 27 (phần việc thành viên 4/4), ~1,5 phút

"Em là Hồ Anh Vũ, B26CHAT048, phụ trách khâu Build & Release của container với Policy và Compliance as Code — pha 2, 6, 7.
- **Pha 2**, Conftest + `docker_security.rego`: kiểm Dockerfile *trước khi build* — 4 nhóm luật, 13 ca kiểm thử.
- **Pha 6**, Dockle 0.4.15: kiểm *image thành phẩm* theo CIS — bắt bí mật trong layer, chạy root. Cũng pha 6, `runtime.rego`: kiểm *container đang chạy* qua `docker inspect` — 7 ca kiểm thử.
- **Pha 7**, `conftest verify`: chạy lại toàn bộ luật trước khi bàn giao.
Em cũng đóng gói image đã vá `deploy/Dockerfile.hotfix`: ghim digest image gốc, chỉ chép 2 route đã vá, `USER 65532`, nhãn OCI, HEALTHCHECK.
Kết quả: verify **19/19**; fixture **exit 1** với 6 vi phạm/4 nhóm; Dockle trên image đã vá **0 FATAL/WARN**, image đóng gói sai bị FATAL.
Ý chính: em kiểm ở **ba thời điểm** — công thức (Dockerfile), thành phẩm (image), lúc chạy (container) — vì một cấu hình đúng trên giấy vẫn có thể bị build hoặc chạy sai."

---

## 4. Rego cơ bản — đủ để giải thích code

### 4.1 Conftest đưa gì vào luật? (`input`)
Conftest dùng parser `dockerfile` để biến mỗi lệnh trong Dockerfile thành **một phần tử của mảng `input`**. Chạy thật `conftest parse report/fixtures/Dockerfile.vulnerable --parser dockerfile` (rút gọn):

```json
[
  {"Cmd": "from",    "Stage": 0, "Value": ["node:22-alpine"]},
  {"Cmd": "workdir", "Stage": 0, "Value": ["/juice-shop"]},
  {"Cmd": "copy",    "Stage": 0, "Value": [".", "."]},
  {"Cmd": "run",     "Stage": 0, "Value": ["npm install --only=production"]},
  {"Cmd": "env",     "Stage": 0, "Value": ["API_TOKEN", "supersecret123", "="]},
  {"Cmd": "expose",  "Stage": 0, "Value": ["3000", "22", "3306"]},
  {"Cmd": "cmd",     "Stage": 0, "Value": ["npm", "start"]}
]
```

- `Cmd`: tên lệnh, viết thường (`from`, `user`, `expose`, `env`, `arg`, `label`, `add`...). Comment cũng thành phần tử `Cmd: "comment"`.
- `Stage`: số thứ tự stage (mỗi `FROM` mở một stage mới: 0, 1, 2...).
- `Value`: các tham số của lệnh. Lưu ý **ENV** được tách thành bộ ba `[khóa, giá trị, "="]` — `ENV A=1 B=2` → `["A","1","=","B","2","="]`. **ARG** thì giữ nguyên `["KEY=VALUE"]`.

### 4.2 Cú pháp Rego dùng trong file
| Cú pháp | Nghĩa | Ví dụ trong file |
|---|---|---|
| `package dockerfile` | Tên "không gian" của luật; Conftest gọi bằng `--namespace dockerfile` | dòng 9 |
| `import rego.v1` | Dùng cú pháp Rego v1 (bắt buộc `if`, `contains`) | dòng 11 |
| `x := ...` | Gán hằng/biến (không gán lại được) | `forbidden_ports := {...}` |
| `{...}` / `[...]` | Tập hợp (set) / mảng | `{"22","23"}` là set |
| `deny contains msg if { ... }` | Luật "từng phần": **mỗi lần** thân luật đúng thì thêm `msg` vào tập `deny`. Conftest coi mỗi phần tử của `deny` là **1 FAIL**, của `warn` là **1 WARN** | dòng 30, 40... |
| Thân luật `{ a; b; c }` | Các dòng là **AND**: tất cả phải đúng | |
| Nhiều luật cùng tên | Là **OR**: luật nào đúng cũng thêm vào `deny` | 8 luật `deny` |
| `some x in coll` | "Tồn tại x trong coll" — Rego thử **mọi** x | `some ins in input` |
| `[expr \| some ...; điều kiện]` | Mảng tạo từ điều kiện (comprehension) | `final_users` |
| `not expr` | Đúng khi `expr` sai **hoặc không xác định** | `not contains(...)` |
| `f(x) := ... if ...` | Hàm/giá trị chỉ xác định khi điều kiện đúng | `last_user` |
| *undefined* | Biểu thức không có giá trị (ví dụ lấy phần tử mảng rỗng) → thân luật dừng, coi như sai | `last_user` khi không có USER |
| `with input as X` | Trong test: chạy luật với `input` giả lập là X | file test |

Hàm dựng sẵn dùng trong file: `split`, `concat`, `contains`, `endswith`, `count`, `max`, `sprintf`, `regex.match`.

---

## 5. Giải thích TỪNG DÒNG `policy/docker_security.rego`

### 5.1 Đầu file (dòng 1–11)
```rego
# Policy as Code cho Dockerfile của Juice Shop.
# Mỗi luật đặt tại điểm thực thi đúng thay vì các "original check" dễ bị qua mặt: ...
#   chạy: conftest test <Dockerfile> -p policy/ --namespace dockerfile
package dockerfile
import rego.v1
```
- Các dòng `#` là chú thích: tóm tắt 4 nhóm luật và cách chạy. Ý quan trọng: *"thay vì các original check dễ bị qua mặt"* — tức nhóm không kiểm hình thức (có USER, có EXPOSE) mà kiểm đúng chỗ quyết định an toàn.
- `package dockerfile`: mọi luật trong file thuộc gói `dockerfile`. Lệnh `--namespace dockerfile` bảo Conftest chỉ chạy gói này (vì thư mục `policy/` còn gói `compose` của F03).
- `import rego.v1`: bật cú pháp chuẩn Rego v1.

### 5.2 Hằng số (dòng 13–16)
```rego
forbidden_ports := {"22", "23", "2375", "2376", "3306", "5432", "6379", "27017"}
required_labels := {"org.opencontainers.image.source", "org.opencontainers.image.revision"}
```
- `forbidden_ports`: **tập** cổng cấm khai báo, viết dạng chuỗi vì `Value` của Dockerfile là chuỗi.
  | Cổng | Dịch vụ | Vì sao nguy hiểm |
  |---|---|---|
  | 22 | SSH | Đăng nhập từ xa vào container → bề mặt brute-force, thêm credential cần quản lý |
  | 23 | Telnet | Như SSH nhưng **không mã hóa**, lộ mật khẩu trên đường truyền |
  | 2375 / 2376 | Docker daemon API (HTTP / TLS) | Ai gọi được API là tạo container privileged, mount `/` của host → chiếm máy chủ |
  | 3306 | MySQL | Cơ sở dữ liệu |
  | 5432 | PostgreSQL | Cơ sở dữ liệu |
  | 6379 | Redis | Mặc định không mật khẩu; kỹ thuật kinh điển dùng `CONFIG SET` ghi khóa SSH → chiếm máy |
  | 27017 | MongoDB | Bản cũ mặc định không xác thực; làn sóng tống tiền 2017 xóa hàng chục nghìn CSDL lộ ra Internet |
- `required_labels`: 2 nhãn OCI bắt buộc — `source` (URL mã nguồn) và `revision` (commit build ra image).

### 5.3 Hàm và giá trị phụ trợ (dòng 18–27)
```rego
uid_of(u) := split(u, ":")[0]
```
- Lấy UID từ chuỗi `USER uid[:gid]`. `split("0:1000", ":")` → `["0","1000"]`, lấy phần tử `[0]` → `"0"`.
- **Vì sao quan trọng:** phiên bản cũ so sánh nguyên chuỗi với `"root"`/`"0"` → `USER 0:1000` lọt (UID 0 là root, group 1000 không làm bớt quyền). Tách UID trước dấu `:` bịt lỗ này; có 2 ca test riêng (`0:1000`, `root:1000`).

```rego
final_stage := max([ins.Stage | some ins in input])
```
- Comprehension: duyệt mọi lệnh, gom số `Stage` thành mảng, lấy **lớn nhất** = stage cuối.
- **Vì sao:** Dockerfile nhiều stage (build ở stage 0, chạy ở stage 1). Chỉ stage cuối tạo ra image chạy thật. Dockerfile gốc của Juice Shop chính là 2 stage: `node:24 AS installer` → `distroless`.

```rego
final_users := [ins.Value[0] | some ins in input; ins.Stage == final_stage; ins.Cmd == "user"]
```
- Mảng giá trị của mọi lệnh `USER` **trong stage cuối**, theo thứ tự xuất hiện. `USER` ở stage builder bị bỏ qua — đúng với cách Docker chạy.

```rego
last_user := final_users[count(final_users) - 1] if count(final_users) > 0
```
- Lấy `USER` **cuối cùng** của stage cuối (lệnh USER sau ghi đè lệnh trước — ví dụ `USER 10001` rồi `USER root` thì image chạy root).
- `if count(...) > 0`: nếu không có USER thì `last_user` *không xác định* → các luật dùng `last_user` tự động không kích hoạt (để luật "thiếu USER" xử lý riêng, không báo trùng).

### 5.4 LEAST-PRIVILEGE (dòng 29–45)
```rego
deny contains msg if {
	count(final_users) == 0
	msg := "LEAST-PRIVILEGE: final stage has no explicit USER; ... (CIS Docker 4.1; PCI-DSS 2.2; NIST SP 800-190)"
}
```
- Luật 1: stage cuối **không có USER nào** → FAIL. Docker mặc định chạy bằng user của base image — với `node:22-alpine` là root. Luật **không đoán** base image; bắt khai báo rõ ràng.
- Thông báo trích luôn điều khoản: CIS 4.1 (tạo user riêng cho container), PCI-DSS 2.2 (cấu hình an toàn, đặc quyền tối thiểu), NIST 800-190.

```rego
deny contains msg if {
	uid_of(last_user) in {"root", "0"}
	msg := sprintf("LEAST-PRIVILEGE: final USER '%s' runs as root (UID 0), regardless of group. ...", [last_user])
}
```
- Luật 2: USER cuối có UID là `root` hoặc `0` → FAIL, bất kể group. `sprintf` chèn giá trị thật vào thông báo để người sửa biết dòng nào sai.

```rego
warn contains msg if {
	last_user
	not uid_of(last_user) in {"root", "0"}
	not regex.match(`^[0-9]+(:[0-9]+)?$`, last_user)
	msg := sprintf("LEAST-PRIVILEGE: final USER '%s' is not a fixed numeric UID. (CIS Docker 4.1)", [last_user])
}
```
- Luật 3 (**WARN**, không chặn): có USER, không phải root, nhưng **không phải số** (ví dụ `USER node`, `USER ${APP_UID}`).
- Regex `^[0-9]+(:[0-9]+)?$`: chỉ toàn chữ số, tùy chọn `:` + số group.
- **Vì sao nên dùng số:** tên user được tra trong `/etc/passwd` *của image* — base image khác có thể ánh xạ tên đó sang UID khác; và Kubernetes với `runAsNonRoot: true` **không thể xác minh** user dạng tên nên từ chối khởi động container.

### 5.5 ATTACK-SURFACE (dòng 47–56)
```rego
port_number(raw) := split(raw, "/")[0] # bỏ hậu tố /tcp, /udp
```
- `EXPOSE 3306/tcp` → `Value` là `"3306/tcp"` → cắt còn `"3306"`. Có ca test riêng cho dạng có giao thức.

```rego
deny contains msg if {
	some ins in input
	ins.Cmd == "expose"
	some raw in ins.Value
	port_number(raw) in forbidden_ports
	msg := sprintf("ATTACK-SURFACE: EXPOSE '%s' covers administrative/database port %s. (CIS Docker 5.8; NIST SP 800-190)", [raw, port_number(raw)])
}
```
- Với **mỗi** lệnh EXPOSE, với **mỗi** cổng trong lệnh: nếu thuộc tập cấm → 1 FAIL. Vì vậy `EXPOSE 3000 22 3306` sinh **2 FAIL** (22 và 3306) — đó là lý do có 6 vi phạm mà chỉ 4 nhóm.
- Luật xét **mọi stage** (không chỉ stage cuối) — nghiêm hơn, chấp nhận được vì không ai cần EXPOSE cổng quản trị ở stage build.

### 5.6 SUPPLY-CHAIN — nhãn nguồn gốc (dòng 58–65)
```rego
label_blob := concat(" ", [concat(" ", ins.Value) | some ins in input; ins.Cmd == "label"])
```
- Gom mọi tham số của mọi lệnh `LABEL` thành **một chuỗi lớn** cách nhau bởi dấu cách. Lý do: một LABEL có thể khai báo nhiều cặp khóa–giá trị, nhiều LABEL rải rác — gom lại cho dễ tìm.

```rego
deny contains msg if {
	some req in required_labels
	not contains(label_blob, req)
	msg := sprintf("SUPPLY-CHAIN: missing provenance label '%s' (...chưa đánh giá đạt mức SLSA). (OCI image-spec; NIST SSDF)", [req])
}
```
- Với mỗi nhãn bắt buộc: nếu chuỗi gom **không chứa** tên nhãn → 1 FAIL. Thiếu cả 2 → 2 FAIL.
- Thông báo cố ý ghi "chưa đánh giá đạt mức SLSA": nhãn là thông tin **tự khai**, giúp truy vết, nhưng không phải bằng chứng ký số. Đây là ranh giới trung thực, báo cáo cũng ghi rõ.

### 5.7 SUPPLY-CHAIN — base image và ADD (dòng 67–87)
```rego
deny contains msg if {
	some ins in input
	ins.Cmd == "from"
	endswith(ins.Value[0], ":latest")
	msg := sprintf("SUPPLY-CHAIN: base image '%s' uses :latest; pin a version or digest. ...", [ins.Value[0]])
}
```
- `FROM xxx:latest` → FAIL. Tag `latest` trôi theo thời gian → image build hôm nay khác hôm qua.

```rego
deny contains msg if {
	some ins in input
	ins.Cmd == "add"
	msg := "SUPPLY-CHAIN: use COPY instead of ADD to avoid remote/implicit extraction. (CIS Docker 4.9)"
}
```
- Có lệnh `ADD` → FAIL. `ADD` làm thêm 2 việc ngầm: **tải từ URL** và **tự giải nén tar** — cả hai ngoài kiểm soát. `COPY` chỉ chép tệp cục bộ.

```rego
warn contains msg if {
	some ins in input
	ins.Cmd == "from"
	not contains(ins.Value[0], "@sha256:")
	not endswith(ins.Value[0], ":latest")
	msg := sprintf("SUPPLY-CHAIN: base image '%s' is not pinned by digest (...). (CIS Docker Benchmark §4; NIST SSDF)", [ins.Value[0]])
}
```
- WARN khi base image không ghim digest (và không phải `:latest`, để không báo trùng với luật trên). Là **khuyến nghị** vì ghim digest có đánh đổi: an toàn tái lập nhưng phải chủ động cập nhật để nhận bản vá bảo mật.
- `Dockerfile.hotfix` của nhóm ghim `bkimminich/juice-shop@sha256:8739...` → không có WARN nào.

### 5.8 SECRET-IN-IMAGE — luật riêng của nhóm (dòng 89–114)
```rego
secret_key := `(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)`
```
- Regex tên khóa nghi là bí mật. `(?i)` = không phân biệt hoa thường. `api[_-]?key` khớp `apikey`, `api_key`, `api-key`.

```rego
deny contains msg if {
	some ins in input
	ins.Cmd == "env"
	some i, key in ins.Value
	i % 3 == 0
	i + 1 < count(ins.Value)
	regex.match(secret_key, key)
	ins.Value[i + 1] != ""
	msg := sprintf("SECRET-IN-IMAGE: ENV '%s' hardcodes a credential into the image (exposed via docker history); ... (CIS Docker 4.10; GDPR Art.32; PCI-DSS 8.2.1)", [key])
}
```
- `some i, key in ins.Value`: duyệt cả **vị trí** `i` và **giá trị**.
- `i % 3 == 0`: vì ENV tách thành bộ ba `[khóa, giá trị, "="]`, khóa luôn ở vị trí 0, 3, 6... → chỉ xét khóa, không xét giá trị.
- `i + 1 < count(...)`: chắc chắn có phần tử giá trị phía sau (tránh lỗi chỉ số).
- `regex.match(secret_key, key)`: tên khóa trông như bí mật.
- `ins.Value[i + 1] != ""`: giá trị **không rỗng** — `ENV API_TOKEN=` (rỗng, để nạp lúc chạy) thì không chặn.
- Với `ENV API_TOKEN=supersecret123`: `Value = ["API_TOKEN","supersecret123","="]`, i=0, khóa khớp `token`, giá trị khác rỗng → FAIL.

```rego
deny contains msg if {
	some ins in input
	ins.Cmd == "arg"
	some tok in ins.Value
	contains(tok, "=")
	regex.match(secret_key, split(tok, "=")[0])
	split(tok, "=")[1] != ""
	msg := sprintf("SECRET-IN-IMAGE: ARG '%s' bakes a credential default into the image. ...", [split(tok, "=")[0]])
}
```
- ARG dạng `["DB_PASSWORD=p@ss"]`: có dấu `=` (có giá trị mặc định), phần trước `=` khớp regex, phần sau khác rỗng → FAIL.
- `ARG DB_PASSWORD` (không mặc định) thì **không** chặn — đúng, vì giá trị truyền lúc build. Lưu ý: ngay cả khi truyền bằng `--build-arg`, giá trị vẫn có thể hiện trong `docker history` nếu được dùng trong `RUN` → cách đúng là `RUN --mount=type=secret`.

### 5.9 Áp vào `Dockerfile.vulnerable` — ra đúng 6 FAIL + 1 WARN
| # | Luật | Dòng gây lỗi | Thông báo (rút gọn) |
|---|---|---|---|
| 1 | ATTACK-SURFACE | `EXPOSE 3000 22 3306` | EXPOSE '22' covers administrative/database port 22 |
| 2 | ATTACK-SURFACE | (cùng dòng) | EXPOSE '3306' ... port 3306 |
| 3 | LEAST-PRIVILEGE | không có `USER` | final stage has no explicit USER |
| 4 | SECRET-IN-IMAGE | `ENV API_TOKEN=supersecret123` | ENV 'API_TOKEN' hardcodes a credential |
| 5 | SUPPLY-CHAIN | thiếu LABEL | missing provenance label '...revision' |
| 6 | SUPPLY-CHAIN | thiếu LABEL | missing provenance label '...source' |
| W | SUPPLY-CHAIN (warn) | `FROM node:22-alpine` | not pinned by digest |

Kết quả dòng cuối của Conftest: `10 tests, 3 passed, 1 warning, 6 failures` → **exit 1**. (Nếu hỏi "10 tests": Conftest tự đếm theo số luật và số thông báo; con số cần nhớ là **6 failures = 6 vi phạm, exit 1**.)

---

## 6. Giải thích 13 ca kiểm thử (`policy/docker_security_test.rego`)

Ý tưởng: **kiểm thử chính bộ luật**, giống unit test cho code. Mỗi ca dùng `with input as <Dockerfile giả lập>` rồi khẳng định `deny` có/không có thông báo mong đợi. Chạy bằng `conftest verify -p policy` (ra 19/19 vì cộng 6 ca của `compose_test.rego`).

`good` (dòng 8–15) là một Dockerfile **đúng** 2 stage giống Juice Shop gốc: builder `node:24`, stage cuối distroless, có nhãn OCI, `USER 65532`, `EXPOSE 3000`, `ENV NODE_ENV=production`.

| # | Tên ca | Đầu vào | Khẳng định | Chống kiểu lách / lý do |
|---|---|---|---|---|
| 1 | `test_good_dockerfile_passes` | `good` | `count(deny) == 0` | **Không báo nhầm** cái đúng (chống false positive) |
| 2 | `test_missing_user_denied` | `array.slice(good,0,1)` = chỉ còn lệnh FROM | có "no explicit USER" | Thiếu USER phải bị chặn |
| 3 | `test_root_user_denied` | `USER root` | có "runs as root" | Root bằng tên |
| 4 | `test_root_uid_zero_denied` | `USER 0:0` | có "runs as root" | Root bằng số |
| 5 | `test_root_uid_with_nonzero_group_denied` | `USER 0:1000` | có "runs as root" | **Lách bằng group** — bản cũ lọt, nay bịt |
| 6 | `test_root_name_with_group_denied` | `USER root:1000` | có "runs as root" | Như trên, dạng tên |
| 7 | `test_builder_user_does_not_cover_final` | USER 10001 ở stage 0, stage 1 không có USER | có "no explicit USER" | **Lách đa stage** — USER ở builder không tính |
| 8 | `test_forbidden_port_denied` | `EXPOSE 3000 22` | có "port 22" | Cổng cấm lẫn trong danh sách |
| 9 | `test_forbidden_port_with_proto_denied` | `EXPOSE 3306/tcp` | có "port 3306" | **Lách bằng hậu tố giao thức** |
| 10 | `test_missing_provenance_label_denied` | có USER + EXPOSE, không LABEL | có "org.opencontainers.image.source" | Thiếu nhãn nguồn gốc |
| 11 | `test_add_instruction_denied` | `good` + `ADD http://x/y /y` | có "use COPY instead of ADD" | ADD tải từ xa |
| 12 | `test_secret_env_denied` | `ENV API_TOKEN=abc123` | có "SECRET-IN-IMAGE" | Bí mật trong ENV |
| 13 | `test_secret_arg_denied` | `ARG DB_PASSWORD=p@ss` | có "SECRET-IN-IMAGE" | Bí mật trong ARG mặc định |

Cách nói: "Bộ luật có ca kiểm thử cho **từng kiểu lách đã biết**: root kèm group, USER ở stage builder, cổng có hậu tố /tcp. Mỗi lần sửa luật, verify chạy lại để chắc không làm hỏng luật cũ — giống kiểm thử hồi quy."

---

## 7. Ba lớp kiểm: Conftest (Dockerfile) → Dockle (image) → `runtime.rego` (container)

| Lớp | Thời điểm | Công cụ | Bắt được gì mà lớp khác không |
|---|---|---|---|
| Công thức | Trước build (pha Build) | Conftest + `docker_security.rego` | Sai từ thiết kế: thiếu USER, cổng cấm, ENV bí mật, thiếu nhãn — **rẻ nhất để sửa** |
| Thành phẩm | Sau build (pha Release) | Dockle 0.4.15 (CIS-DI-xxxx) | Bí mật trong **tệp** bị COPY vào (ví dụ `.env`), quyền setuid, image thực tế chạy root |
| Lúc chạy | Khi container đã chạy (pha Operate) | Conftest + `runtime.rego` trên `docker inspect` | Cấu hình **chạy** sai dù image đúng: privileged, không bỏ capability, không giới hạn CPU/PID, publish cổng ra mọi giao diện |

`report/policy/runtime.rego` (7 ca kiểm thử trong `runtime_test.rego`), giải thích nhanh từng luật:
- `RES-02`: `NanoCpus <= 0` → không giới hạn CPU → một container có thể ăn hết CPU máy chủ (từ chối dịch vụ).
- `RES-03`: `PidsLimit` không > 0 → không giới hạn số tiến trình → **fork bomb** làm treo máy chủ.
- `PRIV-01`: `Privileged == true` → container gần như toàn quyền trên host.
- `PRIV-02`: `User` phải là **UID số ≥ 1** (regex `^[1-9][0-9]*(:[0-9]+)?$` — chữ số đầu từ 1 nên loại `0`).
- `PRIV-03`: phải có `CapDrop: ["ALL"]` — bỏ mọi capability Linux.
- `PRIV-04`: phải có `no-new-privileges:true` — chặn leo thang quyền qua tệp setuid.
- `NET-01`: cổng publish phải bind `127.0.0.1`.
- `F03 NET-02`: container không gắn nhãn `lab.exposure=edge` thì không được có cổng host (luật của F03 kiểm lại lúc chạy).
- `object.get(obj, key, mặc_định)`: lấy trường an toàn khi trường thiếu (docker inspect có thể không có `Labels`).
- Ca `test_default_container_fails`: container "mặc định" vi phạm đúng **6** luật — chứng minh mặc định Docker không an toàn.

---

## 8. Hậu quả an ninh của TỪNG vi phạm — và vì sao

### 8.1 Chạy bằng root (LEAST-PRIVILEGE)
- **Vì sao nguy hiểm:** nếu không bật user namespace remap, **UID 0 trong container chính là UID 0 trên máy chủ**, chỉ bị giới hạn bởi namespace/cgroup/capability. Lớp ngăn cách mỏng hơn nhiều so với máy ảo.
- **Kịch bản:** ứng dụng có lỗ hổng thực thi mã (RCE) → kẻ tấn công có shell root trong container → (1) sửa mã ứng dụng, cài web shell để bám trụ; (2) đọc mọi tệp, kể cả bí mật mount với quyền root-only; (3) ghi vào volume dùng chung với tư cách root; (4) kết hợp lỗ hổng runtime/kernel để **thoát container**.
- **Ví dụ thật:** **CVE-2019-5736 (runc)** — tiến trình **root trong container** ghi đè tệp `runc` trên máy chủ, giành root host khi có `docker exec` tiếp theo. Chạy non-root làm khai thác kiểu này khó hơn rất nhiều.
- **Liên hệ F01:** F01 mới chứng minh *vượt xác thực*, chưa phải RCE. Non-root là **phòng thủ theo chiều sâu**: khoanh vùng thiệt hại cho lỗ hổng *giả định* chưa biết. (Báo cáo mục 5.4 nói đúng ý này — đừng nói quá thành "F01 dẫn tới chiếm máy chủ".)
- **Chuẩn:** CIS Docker 4.1, PCI-DSS 2.2, NIST SP 800-190.

### 8.2 USER dạng tên, không phải số (WARN)
- Tên tra theo `/etc/passwd` của image → đổi base image có thể đổi UID; Kubernetes `runAsNonRoot` không xác minh được → container bị từ chối, hoặc người vận hành tắt kiểm tra cho "chạy được" → mất bảo vệ.
- **Bẫy của UID số không kèm GID** (đã chạy thử `docker run --user 65532 quay.io/centos/centos:stream9`): ra `uid=65532 gid=0(root)`, `whoami: cannot find name for user ID 65532`, `HOME=/`. UID không có trong `/etc/passwd` thì Docker gán **group root (0)** — không phải root, nhưng thừa quyền với tệp của group 0. Ghi `--user 65532:65532` thì ra `uid=65532 gid=65532`. Image của nhóm không dính vì distroless đã có user `nonroot` 65532:65532; bẫy chỉ xảy ra khi đem cùng dòng `USER 65532` sang base image khác.

### 8.3 Khai báo cổng quản trị/CSDL (ATTACK-SURFACE)
- **Sự thật kỹ thuật:** `EXPOSE` **tự nó không mở cổng** — chỉ là tài liệu. Nói rõ điều này để không bị bắt bẻ.
- **Nhưng vẫn có hậu quả thật:**
  1. `docker run -P` **publish mọi cổng đã EXPOSE** ra cổng ngẫu nhiên trên host → một lệnh tiện tay là SSH/MySQL lộ ra.
  2. Một số công cụ tự động (reverse proxy tự khám phá dịch vụ, nền tảng PaaS) đọc cổng EXPOSE để định tuyến.
  3. Là **tín hiệu thiết kế sai**: có sshd trong container (container nên chạy 1 tiến trình; SSH thêm mật khẩu/khóa phải quản lý, thêm mục tiêu brute-force); có CSDL chung container với ứng dụng (chung "vùng nổ": chiếm app là chiếm dữ liệu).
- **Theo từng cổng:** 2375 không TLS → điều khiển Docker daemon = root host (sâu **Graboid** 2019 lây qua Docker daemon lộ ra Internet để đào tiền ảo); Redis 6379 không mật khẩu → ghi khóa SSH qua `CONFIG SET`; MongoDB 27017 → đợt tống tiền 2017.
- **Chuẩn:** CIS Docker 5.8 (chỉ mở cổng cần thiết), NIST 800-190.

### 8.4 Thiếu nhãn nguồn gốc OCI (SUPPLY-CHAIN — provenance)
- **Hậu quả:** khi có sự cố, **không truy được** image đang chạy build từ repo nào, commit nào → không biết phải vá ở đâu, không xác định được những image nào chứa commit lỗi để thu hồi.
- **Ví dụ thật:** tháng 12/2021 **Log4Shell (CVE-2021-44228)** — các tổ chức phải lục tung xem image nào chứa log4j. Ai có SBOM + nhãn nguồn gốc thì trả lời trong vài giờ.
- **Ranh giới:** nhãn tự khai **có thể làm giả** → hỗ trợ truy vết, **không** chứng minh tính toàn vẹn. Muốn chứng minh cần ký số (cosign) và provenance SLSA. Báo cáo nói rõ: *chưa đánh giá đạt SLSA*.

### 8.5 Base image `:latest` / không ghim digest
- **Hậu quả:** tag di động → image đã kiểm thử ≠ image triển khai; không tái lập được bản build; không rollback chính xác; nếu tài khoản phát hành base image bị chiếm và tag bị trỏ sang image độc, lần build sau **tự động kéo mã độc**.
- **Đánh đổi (nói để thể hiện hiểu sâu):** ghim digest thì bất biến nhưng **không tự nhận bản vá** → cần bot (Renovate/Dependabot) mở PR cập nhật digest. Đó là lý do nhóm để mức WARN.

### 8.6 Dùng ADD
- Tải từ URL **không kiểm checksum** (máy chủ nguồn bị chiếm hoặc nội dung đổi → build kéo nội dung khác); **tự giải nén tar** (tệp nén độc có thể chứa đường dẫn/symlink bất thường, hoặc "bom" giải nén). CIS Docker 4.9. Nếu thật cần tải, dùng `ADD --checksum=sha256:...` (BuildKit) hoặc `RUN curl` + kiểm hash.

### 8.7 Bí mật trong ENV/ARG (SECRET-IN-IMAGE — luật riêng của nhóm)
- **Vì sao lộ:** ENV nằm trong **cấu hình image** — `docker inspect` hiện `Config.Env`, `docker history` hiện lệnh tạo layer. Xóa ở layer sau **không xóa** layer cũ.
- **Ai đọc được:** bất kỳ ai `pull` được image: registry công khai do cấu hình nhầm, máy CI, bộ nhớ đệm build, đồng nghiệp, nhà thầu.
- **Lộ thêm lúc chạy:** biến môi trường được kế thừa sang mọi tiến trình con, nằm trong `/proc/<pid>/environ`, hay bị in ra log lỗi, crash dump, công cụ báo lỗi.
- **Không xoay vòng được:** đổi mật khẩu phải build lại image; image cũ vẫn chứa mật khẩu cũ.
- **Ví dụ thật:** sự cố **Codecov (4/2021)** bắt đầu từ lỗi trong quy trình tạo **Docker image** khiến kẻ tấn công trích được một credential, rồi sửa script Bash Uploader dùng trong CI của hàng nghìn khách hàng. Ngoài ra có nghiên cứu học thuật quét hàng trăm nghìn image công khai trên Docker Hub và tìm thấy khóa bí mật trong một tỷ lệ đáng kể image *(Dahlmanns et al., ACM AsiaCCS 2023 — nếu trích con số cụ thể ~8,5% thì nên kiểm tra lại nguồn trước khi nói)*.
- **Chuẩn:** CIS Docker 4.10, PCI-DSS 8.2.1, GDPR Điều 32.
- **Cách đúng:** `RUN --mount=type=secret,id=...` (BuildKit, không ghi vào layer); nạp lúc chạy qua Docker/Kubernetes secrets hoặc Vault; biến `*_FILE` trỏ tới tệp secret.

---

## 9. Những gì bộ luật CHƯA bắt — đã chạy thử thật (dùng cho hỏi đáp & hướng mở rộng)

> Nói chủ động: "Nhóm tự tấn công bộ luật của mình và tìm ra các điểm sau." Đây là điểm cộng: thể hiện hiểu giới hạn, không tô vẽ.
> Chạy bằng Conftest v0.71.1 trên các Dockerfile thử nghiệm (đều có nhãn OCI + USER 10001 để chỉ còn đúng 1 khác biệt).

| # | Dockerfile thử | Kết quả thật | Hậu quả an ninh | Cách vá luật |
|---|---|---|---|---|
| B1 | `FROM node` (không tag = latest ngầm) | **exit 0**, chỉ WARN | Giống `:latest`: image trôi, kéo nhầm bản độc | Coi "không có tag và không có digest" là `:latest` → deny |
| B2 | `EXPOSE 3300-3310 2370-2380` | **exit 0** | Dải cổng chứa 2375/2376 (Docker API) lọt | Tách dải `a-b`, kiểm từng cổng cấm có nằm trong dải |
| B3 | `ENV DB_PASS=... AUTH=Bearer...` | Chỉ bắt `AWS_SECRET_ACCESS_KEY`; **`DB_PASS`, `AUTH` lọt** | Mật khẩu, token lộ qua `docker history` | Mở rộng regex (`pass`, `pwd`, `auth`, `bearer`), thêm **dò theo giá trị** (mẫu `AKIA…`, `ghp_…`, độ ngẫu nhiên/entropy) |
| B4 | `LABEL note="org.opencontainers.image.source org.opencontainers.image.revision"` | **exit 0** | Nhãn bắt buộc chỉ là "chữ nằm đâu đó", không có giá trị thật → mất truy vết | Phân tích cặp khóa=giá trị, yêu cầu **khóa** đúng tên và **giá trị không rỗng** |
| B5 | `ARG APP_UID=0` + `USER ${APP_UID}` | **exit 0**, chỉ WARN | **Thực chất chạy root** mà qua cổng | Thay biến bằng giá trị mặc định của ARG trước khi kiểm; hoặc nâng "USER không phải số" lên deny |
| B6 | `RUN curl -H "Authorization: token ghp_..." https://x/y.sh \| sh` | **exit 0** | Token nằm trong `docker history`; tải-và-chạy script không kiểm chứng | Luật dò bí mật trong `RUN`; luật cấm `curl \| sh` |
| B7 | `ENV DB_PASSWORD_FILE=/run/secrets/db TOKEN_URL=https://...` | **exit 1 — chặn nhầm** (false positive) | Làm phiền người dùng → họ tìm cách tắt luật | Cho phép hậu tố `_FILE` (như `compose.rego` đã làm), loại `_URL` |
| B8 | `USER node` | exit 0, WARN | Xem 8.2 | Có thể nâng lên deny cho môi trường Kubernetes |
| B9 | `COPY .env /app/.env` | **exit 0** | Tệp bí mật nằm trong layer | **Thiết kế:** đây là việc của Dockle (kiểm thành phẩm) và `.dockerignore`; có thể thêm luật cảnh báo COPY tệp tên nhạy cảm |
| B10 | `ARG DB_PASSWD==x` (giá trị bắt đầu bằng `=`) | **exit 0** — `split` cắt ở mọi dấu `=` → `["DB_PASSWD","","x"]`, `[1]` rỗng | Mật khẩu base64 hay có `=` ở đầu/cuối → lọt | Xét phần sau dấu `=` **đầu tiên**: `indexof(tok, "=") < count(tok) - 1` |

Cách nói khi bị hỏi "luật có lách được không?": "Có, nhóm đã thử và ghi nhận 10 trường hợp, ví dụ USER bằng biến ARG mặc định 0. Vì vậy nhóm không dựa vào một lớp: Dockle kiểm image thành phẩm và `runtime.rego` kiểm container đang chạy — `runtime.rego` đòi **UID số ≥ 1** từ `docker inspect`, nên trường hợp B5 sẽ bị chặn ở lớp chạy. Các điểm còn lại là hướng mở rộng của bộ luật."

> Lưu ý trung thực: B5 bị `runtime.rego` chặn là suy luận từ mã luật (PRIV-02 đọc `Config.User` thực tế sau khi build — với `USER ${APP_UID}` và `APP_UID=0`, giá trị sẽ là `0`, không khớp regex `^[1-9]...`); nhóm chưa dựng container riêng để chạy thử trường hợp này.

---

## 10. Hướng mở rộng (nói theo 3 tầng thời gian)

**Ngắn hạn — làm cứng bộ luật hiện có**
- Vá 10 điểm ở mục 9, mỗi điểm thêm **một ca kiểm thử** (đúng tinh thần Test-Driven Security: tìm ra lỗ → viết ca đỏ → sửa luật → xanh).
- Thêm luật CIS mục 4 còn thiếu: **4.6 HEALTHCHECK** (hotfix đã có nhưng luật chưa bắt buộc), **4.7** không chạy lệnh update đứng riêng, **4.8** gỡ setuid/setgid, **4.2** chỉ cho base image từ danh sách registry tin cậy (allowlist: distroless, Docker Official Images).
- Đo **độ phủ luật**: `opa test --coverage` để biết dòng luật nào chưa có ca kiểm thử.
- Cơ chế **ngoại lệ có thời hạn** (waiver): cho phép bỏ qua 1 luật cho 1 image kèm lý do và ngày hết hạn, thay vì để người dùng tắt cả cổng.

**Trung hạn — từ "khai báo" sang "bằng chứng"**
- **Ký image** bằng Sigstore **cosign**, sinh **SBOM** và **provenance SLSA** ngay lúc build (`docker buildx build --sbom=true --provenance=true`). Nhãn OCI hiện tại tự khai; chữ ký mới chứng minh "image này đúng do pipeline của nhóm build từ commit X".
- Bí mật lúc build qua `RUN --mount=type=secret`; lúc chạy qua Vault/Kubernetes Secrets; quét bí mật trong layer bằng Trivy secret scanner.
- **Rootless Docker / userns-remap**: UID 0 trong container ánh xạ thành UID thường trên host → kể cả chạy root cũng giảm thiệt hại. Thêm seccomp/AppArmor profile.

**Dài hạn — chính sách thống nhất toàn vòng đời**
- Dùng **cùng ngôn ngữ Rego** cho Kubernetes: **OPA Gatekeeper** (hoặc Kyverno) làm *admission controller* — cụm từ chối mọi Pod chạy root, không `readOnlyRootFilesystem`, image không có chữ ký. Lúc đó luật không chỉ kiểm file mà **cưỡng chế ở nơi chạy**.
- Phân phối bộ luật như một sản phẩm: đóng gói, đánh phiên bản, các nhóm kéo về bằng `conftest pull` từ registry OCI → một nguồn chính sách cho cả tổ chức.
- Đo lường: % image đạt chính sách, thời gian từ lúc phát hiện tới lúc sửa (MTTR), số ngoại lệ đang mở.

---

## 11. Câu hỏi phản biện — trả lời mẫu

1. **Sao không lấy lỗi thật mà dựng lỗi giả?** — Image gốc đã đúng. Muốn chứng minh luật *bắt được* thì cần đầu vào sai có kiểm soát; muốn chứng minh *không báo nhầm* thì cần cả đầu vào đúng (bản vá, Dockerfile gốc, hotfix). Nhóm nói rõ đây là fixture, không nhận là lỗi của Juice Shop.
2. **EXPOSE không mở cổng, chặn làm gì?** — Đúng là chỉ khai báo. Nhưng `docker run -P` publish mọi cổng EXPOSE, một số công cụ đọc EXPOSE để định tuyến, và nó báo hiệu thiết kế sai (sshd/CSDL trong container). Phơi nhiễm *thật* được kiểm ở chỗ khác: `compose.rego` (F03) và `docker inspect`.
3. **Đã có Dockle sao còn Conftest?** — Conftest kiểm công thức *trước khi build*, sửa rẻ nhất, chạy cả khi chưa có Docker build; Dockle kiểm thành phẩm, bắt được bí mật trong tệp bị COPY. Hai lớp bổ trợ (xem mục 7).
4. **Nhãn OCI làm giả được, có ý nghĩa gì?** — Đúng, nên nhóm ghi "hỗ trợ truy vết, chưa đạt SLSA". Bước tiếp theo là ký cosign + provenance SLSA (mục 10).
5. **Sao WARN mà không deny cho digest?** — Ghim digest là đánh đổi: an toàn tái lập nhưng không tự nhận bản vá. Ép deny mà không có bot cập nhật thì image sẽ cũ dần. Hotfix của nhóm vẫn ghim digest.
6. **Regex bí mật có báo nhầm không?** — Có, nhóm đã thử: `DB_PASSWORD_FILE`, `TOKEN_URL` bị chặn nhầm; `DB_PASS` lại lọt. Đây là giới hạn của dò theo tên; hướng mở rộng là dò theo giá trị + cho phép `*_FILE`.
7. **Sao kiểm stage cuối mà cổng lại kiểm mọi stage?** — USER chỉ có tác dụng ở stage tạo image chạy thật, nên phải đúng stage cuối. Còn cổng quản trị thì không có lý do hợp lệ để khai báo ở bất kỳ stage nào — nghiêm hơn không gây báo nhầm thực tế.
8. **`USER 65532` là ai?** — User `nonroot` có sẵn trong image distroless của Google; Juice Shop gốc dùng nó.
9. **Root trong container có thật sự là root máy chủ?** — Nếu không bật user namespace remap thì cùng UID 0; container chỉ khác ở namespace/cgroup/capability. Đó là lý do CIS 4.1 yêu cầu user riêng.
10. **Luật chạy ở đâu trong pipeline?** — Pha Build của `devsecops/pipeline.sh` (cũng trong GitHub Actions và Git hook): `conftest verify` rồi `conftest test Dockerfile deploy/Dockerfile.hotfix --parser dockerfile`. FAIL thì exit 1, pipeline dừng.
11. **Vì sao gắn GDPR Điều 25(1)?** — Điều 25(1) là bảo vệ dữ liệu *từ khi thiết kế*: image an toàn ngay từ Dockerfile thay vì vá sau khi chạy. Điều 32(1)(d): kiểm thử định kỳ hiệu quả biện pháp — `conftest verify` chạy mỗi lần build.
12. **Có thể bỏ qua cổng bằng cách đổi tên file Dockerfile?** — Pipeline gọi đích danh các Dockerfile được build; muốn chắc hơn thì quét mọi tệp `*Dockerfile*` trong repo, hoặc chuyển sang kiểm ở admission controller (mục 10).
13. **Bộ luật lấy tiêu chuẩn từ đâu?** — CIS Docker Benchmark §4 (image) và §5 (runtime), NIST SP 800-190 (an toàn container), OCI image-spec (nhãn), PCI-DSS, GDPR 25/32. Mỗi thông báo vi phạm **trích sẵn điều khoản** để người sửa biết vì sao. Mapping từng luật, mức khớp (trực tiếp / một phần / tham chiếu) và các trích dẫn nên chỉnh (PCI 8.2.1 là số của v3.2.1 → v4.0 là 8.6.2): mục **14.4**.
14. **Bao lâu chạy một lần, có chậm không?** — Mỗi lần build; Conftest chạy vài giây trong container `openpolicyagent/conftest:v0.71.1`.
15. **Nếu một đội cần mở cổng 5432 hợp lệ?** — Không nên đóng gói CSDL chung image ứng dụng; nếu là image CSDL riêng thì dùng cơ chế ngoại lệ có thời hạn và lý do (mục 10), không sửa tắt luật cho mọi người.

---

## 12. Chất liệu "chém gió" (dùng có chọn lọc)

**Câu chốt đắt giá**
- "Container chạy root vẫn *chạy được* — đó chính là vấn đề: lỗi cấu hình không gây lỗi, nó chờ bị khai thác."
- "Chúng em không kiểm *có lệnh USER không*, mà kiểm *ai thực sự chạy image* — USER ở stage cuối, tách UID khỏi group."
- "Bí mật trong layer giống viết mật khẩu lên tường rồi sơn đè: lớp sơn mới không xóa chữ ở lớp dưới."
- "Mỗi luật đều có ca kiểm thử — chúng em kiểm thử cả công cụ kiểm thử."
- "Shift-left: sửa một dòng Dockerfile mất 1 phút; sửa sau khi image đã chạy ở 100 máy chủ mất cả ngày."
- "Chúng em tự tấn công bộ luật của mình và tìm ra 10 điểm yếu — đó là lý do có ba lớp kiểm, không đặt cược vào một lớp."

**Câu chuyện thực tế (đã kiểm chứng ở mức phổ biến; nói ngắn, không bịa chi tiết)**
- runc **CVE-2019-5736** (2019): root trong container ghi đè runc trên host → root máy chủ.
- **Graboid** (2019): sâu đào tiền ảo lây qua Docker daemon mở cổng 2375 ra Internet.
- **Codecov** (4/2021): lỗi trong quy trình tạo Docker image làm lộ credential → kẻ tấn công sửa script dùng trong CI của khách hàng.
- **Log4Shell** (12/2021): bài học về truy vết thành phần — ai có SBOM/nguồn gốc image thì khoanh vùng nhanh.
- **MongoDB ransom** (2017): CSDL không xác thực lộ ra Internet bị xóa và đòi tiền chuộc hàng loạt.

**Kỹ thuật trả lời khi bí**
- Quy về khung 3 lớp (công thức → thành phẩm → lúc chạy).
- Quy về ranh giới trung thực: "trong phạm vi bốn tình huống", "chưa đánh giá đạt SLSA".
- Không chắc: "Em xin phép kiểm tra lại log trong `report/evidence/` và trả lời sau" — đừng đoán.

---

## 13. Checklist trước giờ G

- [ ] Docker Desktop đang chạy; image `openpolicyagent/conftest:v0.71.1` đã kéo sẵn (chạy demo 1 lần để cache).
- [ ] Chạy thử: `python report/demos/tv4_f04_policy.py` → thấy 19/19 và 4 dòng kết luận "đúng".
- [ ] Mở sẵn trong VS Code 3 tab: `report/fixtures/Dockerfile.vulnerable`, `report/fixtures/Dockerfile.remediated`, `policy/docker_security.rego` — để chỉ code nếu bị hỏi.
- [ ] Phóng to chữ terminal (Ctrl + cuộn) để người ngồi cuối đọc được.
- [ ] Thuộc 3 câu ở mục 1 và các con số: **4 nhóm luật, 6 vi phạm, exit 1, 13 ca, 19/19, UID 10001 / 65532, Dockle 0 FATAL**.
- [ ] Lệnh dự phòng nếu demo hỏng: `docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test report/fixtures/Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile --no-color`

---

## 14. Tổng hợp toàn bộ luật — 3 bộ, 25 luật, 26 ca kiểm thử

Ba bộ luật Rego kiểm **ba thứ khác nhau ở ba thời điểm**. `deny` = **FAIL** (exit 1, pipeline dừng), `warn` = **WARN** (chỉ nhắc, exit 0). Cột "Chuẩn" ở 14.1–14.3 chỉ ghi số hiệu; điều khoản nói gì và luật khớp tới đâu xem **14.4**.

| Bộ luật | Kiểm cái gì | Pha | `input` là gì | Luật | Ca test |
|---|---|---|---|---|---|
| `policy/docker_security.rego` (F04) | `Dockerfile`, `deploy/Dockerfile.hotfix` | Build | mảng các lệnh Dockerfile | 8 deny + 2 warn | 13 |
| `policy/compose.rego` (F03) | `docker-compose.yml` | Deploy (trước `compose up`) | object YAML của compose | 5 deny + 2 warn | 6 |
| `report/policy/runtime.rego` (F03/F04) | `docker inspect` của container đang chạy | Operate | object JSON của container | 8 deny | 7 |

### 14.1 `docker_security.rego` — công thức image (Policy as Code)

| Nhóm | Bắt khi | Mức | Chuẩn |
|---|---|---|---|
| LEAST-PRIVILEGE | Stage cuối **không có `USER`** | FAIL | CIS 4.1, PCI-DSS 2.2, NIST 800-190 |
| | `USER` cuối là root (`root`, `0`, `0:1000`, `root:1000`) | FAIL | CIS 4.1, PCI-DSS 2.2 |
| | `USER` không phải UID số (`USER node`) | WARN | CIS 4.1 |
| ATTACK-SURFACE | `EXPOSE` 22, 23, 2375, 2376, 3306, 5432, 6379, 27017 (cả dạng `22/tcp`), ở mọi stage | FAIL | CIS 5.8, NIST 800-190 |
| SUPPLY-CHAIN | Thiếu nhãn `org.opencontainers.image.source` / `.revision` | FAIL | OCI image-spec, NIST SSDF |
| | `FROM …:latest` | FAIL | CIS §4, NIST SSDF |
| | Dùng `ADD` | FAIL | CIS 4.9 |
| | `FROM` không ghim `@sha256:` | WARN | CIS §4, NIST SSDF |
| SECRET-IN-IMAGE | `ENV` có **tên** khớp `password\|passwd\|secret\|token\|api_key\|access_key\|private_key\|credential` **và** giá trị không rỗng | FAIL | CIS 4.10, GDPR 32, PCI-DSS 8.2.1 |
| | `ARG` như trên, ở giá trị mặc định | FAIL | như trên |

Luật bí mật **chỉ xét tên, không xét giá trị**: `ENV DB_PASSWORD=changeme` vẫn FAIL; `ENV DB_PASSWORD=` và `ARG NPM_TOKEN` (không mặc định) PASS; `ENV AWS=AKIA…` (tên vô hại) lọt — việc của Gitleaks ở pha Code.

### 14.2 `compose.rego` — cấu hình triển khai (Policy as Code, F03)

| Mã | Bắt khi | Mức | Chuẩn |
|---|---|---|---|
| F03 NET-02 | Service **không có nhãn `lab.exposure: edge`** mà vẫn publish cổng → backend đi vòng qua được proxy (nơi chặn `/metrics`, giới hạn tốc độ) | FAIL | luật của nhóm |
| NET-01 | Cổng publish không bind `127.0.0.1` (`"3000:3000"`, `0.0.0.0`) | FAIL | GDPR 32 |
| — | `privileged: true` | FAIL | CIS 5.4 |
| — | Mount `docker.sock` | FAIL | CIS 5.31 |
| — | `environment` có `…PASSWORD=`, `…SECRET=`, `…TOKEN=`, `…API_KEY=` kèm giá trị (`*_FILE` được phép) | FAIL | PCI-DSS 8.2.1, GDPR 32 |
| — | Thiếu `cap_drop: [ALL]` | WARN | CIS 5.3 |
| — | Thiếu `read_only: true` | WARN | CIS 5.12 |

Luật cổng hiểu đủ 3 cách viết `ports` của Compose: chuỗi `"127.0.0.1:3102:8080"`, số `3000`, object `{host_ip, …}`.

### 14.3 `runtime.rego` — container đang chạy (Compliance as Code)

| Mã | Bắt khi |
|---|---|
| RES-02 | Không giới hạn CPU (`NanoCpus` ≤ 0) |
| RES-03 | Không giới hạn số tiến trình (`PidsLimit`) → fork bomb |
| PRIV-01 | `Privileged == true` |
| PRIV-02 | User **không phải UID số ≥ 1** — ở lớp này `node` cũng FAIL (chặt hơn lớp Dockerfile) |
| PRIV-03 | Không `CapDrop: ["ALL"]` |
| PRIV-04 | Không `no-new-privileges:true` |
| NET-01 | Cổng trên host bind khác `127.0.0.1` |
| F03 NET-02 | Container không nhãn `edge` mà có cổng trên host |

Tất cả là FAIL. Lớp này bắt trường hợp **tệp đúng nhưng chạy sai** (ai đó `docker run` tay, override bị quên).

### 14.4 Mapping luật → chuẩn: điều khoản nói gì, luật thực thi tới đâu

**Cách đọc mapping.** Chuẩn nói **phải đạt điều gì** (yêu cầu); luật Rego là **một cách kiểm tự động** yêu cầu đó trên một loại tệp, ở một thời điểm. Vì vậy mỗi dòng mapping có một **mức khớp**:
- ● **Trực tiếp** — luật kiểm đúng điều mục yêu cầu (vd CIS 4.9 "dùng COPY thay ADD" ↔ luật cấm `ADD`).
- ◐ **Một phần** — luật chỉ kiểm một phần yêu cầu, hoặc kiểm ở lớp khác với lớp mà điều khoản nói tới (vd CIS 5.8 nói cổng **đang mở** lúc chạy, luật kiểm cổng **khai báo** trong Dockerfile).
- ○ **Tham chiếu** — chuẩn không có điều mục riêng cho đúng việc này; luật là thực hành tốt **hỗ trợ** tinh thần của chuẩn.

> Câu chốt khi bị hỏi: **"Đạt bộ luật ≠ đạt chứng nhận CIS hay PCI-DSS."** Bộ luật tự động hóa một số điều mục *liên quan tới 4 tình huống*; đánh giá tuân thủ đầy đủ cần kiểm cả host, daemon, quy trình, con người.

**a) Các chuẩn được trích — mỗi chuẩn là loại tài liệu gì**

| Chuẩn | Loại | Phần dùng tới | Ghi chú khi trích |
|---|---|---|---|
| **CIS Docker Benchmark** | Danh mục cấu hình an toàn (checklist), mỗi mục có *Audit* (cách kiểm) + *Remediation* (cách sửa) | §4 *Container Images and Build File* (image/Dockerfile), §5 *Container Runtime* (lúc chạy) | Số mục §5 có thể lệch giữa các phiên bản Benchmark → khi nói, **nêu tên mục** kèm số |
| **NIST SP 800-190** — *Application Container Security Guide* | Hướng dẫn: §3 liệt kê rủi ro, §4 biện pháp tương ứng | §3.1/§4.1 rủi ro image; §3.4/§4.4 rủi ro container | Không có "mục pass/fail" — trích như cơ sở rủi ro |
| **OCI image-spec** | Đặc tả định dạng image | `annotations`: định nghĩa các khóa `org.opencontainers.image.*` | Đặc tả **định nghĩa** khóa, **không bắt buộc** có — "bắt buộc" là chính sách của nhóm |
| **NIST SSDF (SP 800-218)** | Bộ thực hành phát triển phần mềm an toàn (PO/PS/PW/RV) | PS.3 (lưu giữ, dữ liệu nguồn gốc), PW.4 (dùng lại thành phần an toàn, kiểm chứng thành phần lấy về) | Mức thực hành, không phải điều mục kỹ thuật |
| **SLSA** | Khung mức độ an toàn chuỗi cung ứng build | Provenance do **nền tảng build** sinh và **ký** | Chỉ **tham chiếu** — nhãn tự khai không đạt mức SLSA nào |
| **PCI-DSS** | Tiêu chuẩn **bắt buộc** với tổ chức xử lý dữ liệu thẻ | Req 2 (cấu hình an toàn), Req 7 (đặc quyền tối thiểu), Req 8 (xác thực, mật khẩu) | Bản hiện hành là **v4.0.1** (v3.2.1 đã hết hiệu lực 3/2024) — số mục thay đổi, xem ghi chú (d) |
| **GDPR** | Luật EU, yêu cầu **kết quả**, không chỉ định kỹ thuật | Đ.25(1) bảo vệ từ khi thiết kế; Đ.25(2) theo mặc định; Đ.32(1)(b) bí mật/toàn vẹn; Đ.32(1)(d) kiểm thử định kỳ | Luật là **bằng chứng biện pháp kỹ thuật**, không tự làm hệ thống "tuân thủ GDPR" |

**b) `docker_security.rego` (F04) — từng luật**

| Luật | Điều khoản | Điều khoản yêu cầu gì | Luật thực thi tới đâu | Khớp |
|---|---|---|---|:-:|
| Thiếu `USER` / `USER` root | **CIS 4.1** *Ensure that a user for the container has been created* | Tạo user không phải root trong image và chuyển sang user đó bằng `USER`; *Audit* của CIS là xem `Config.User` của container đang chạy có rỗng/root không | Kiểm ngay trên Dockerfile, **chặt hơn** CIS: chỉ tính `USER` ở **stage cuối**, tách UID khỏi group (`0:1000` vẫn là root) | ● |
| | **NIST 800-190 §3.1.2** *Image configuration defects* / §4.1.2 | Image cấu hình chạy với đặc quyền cao hơn cần là một lỗi cấu hình; biện pháp: dùng công cụ **kiểm và cưỡng chế** cấu hình an toàn | Bộ luật chính là "công cụ cưỡng chế" mà §4.1.2 nói tới | ● |
| | **PCI-DSS 2.2** (cấu hình an toàn) | Có tiêu chuẩn cấu hình cho mọi thành phần hệ thống và áp dụng nó | Đúng tinh thần, nhưng "đặc quyền tối thiểu cho tài khoản ứng dụng" là **v4.0 Req 7.2.5** (tài khoản ứng dụng/hệ thống chỉ có quyền tối thiểu cần thiết) | ◐ |
| `USER` không phải số (WARN) | CIS 4.1 (tinh thần) | CIS không đòi UID số | Thắt chặt của nhóm: tên user tra theo `/etc/passwd` của image; Kubernetes `runAsNonRoot` không xác minh được tên | ○ |
| `EXPOSE` cổng quản trị/CSDL | **CIS 5.8** *Ensure that only needed ports are open on the container* | Mục **runtime**: cổng **đang mở** của container chỉ gồm cổng cần thiết | Kéo kiểm tra sang **trước build** trên cổng *khai báo*; `EXPOSE` không tự mở cổng → cổng mở thật được kiểm ở `compose.rego` + `runtime.rego` | ◐ |
| | **NIST 800-190 §3.1.2** | Ví dụ lỗi cấu hình image: chạy dịch vụ không cần thiết như **SSH daemon** | Cổng 22/23 là dấu hiệu có sshd/telnet trong image | ● |
| | (nên thêm) **PCI-DSS v4.0 2.2.4**, **CIS 5.6** | 2.2.4: chỉ bật dịch vụ/giao thức/daemon cần thiết. 5.6: không chạy sshd trong container | Khớp sát hơn PCI 2.2 chung chung | ● |
| Thiếu nhãn `…source` / `…revision` | **OCI image-spec** (annotations) | `source` = URL lấy mã nguồn build image; `revision` = mã phiên bản (commit) trong hệ quản lý mã | Chỉ kiểm **có khóa**; không kiểm giá trị đúng (lỗ B4, mục 9) | ◐ |
| | **NIST SSDF PS.3.2** | Thu thập, bảo vệ, chia sẻ **dữ liệu nguồn gốc** của từng bản phát hành | Nhãn là dữ liệu nguồn gốc **tự khai** | ◐ |
| | **SLSA** | Provenance do nền tảng build sinh ra và **ký**, người dùng xác minh được | Không đạt — vì vậy thông báo ghi "chưa đánh giá đạt mức SLSA" | ○ |
| `FROM …:latest` | CIS §4 (gần nhất: **4.2** *trusted base images*) | Chỉ dùng base image tin cậy, đã kiểm | CIS **không có mục riêng** "cấm `:latest`" — luật là thực hành tốt: tag trôi → image đã kiểm ≠ image triển khai | ○ |
| | **NIST SSDF PW.4** | Dùng lại thành phần đã được bảo đảm an toàn; kiểm chứng thành phần lấy về | `:latest` làm mất khả năng kiểm chứng "đúng bản đã duyệt" | ○ |
| `FROM` không ghim digest (WARN) | CIS §4, SSDF PW.4 | Như trên | **Không phải CIS 4.5** — 4.5 là *Content Trust* (xác minh **chữ ký**), digest chỉ cố định **nội dung** | ○ |
| Dùng `ADD` | **CIS 4.9** *Ensure that COPY is used instead of ADD* | `ADD` tải từ URL và tự giải nén tar → đưa nội dung ngoài kiểm soát vào image | Cấm mọi `ADD` | ● |
| Bí mật trong `ENV`/`ARG` | **CIS 4.10** *Ensure secrets are not stored in Dockerfiles* | Không để bí mật trong Dockerfile (lộ qua `docker history`, `docker inspect`) | **Một phần**: chỉ dò theo **tên khóa**; bí mật dưới tên vô hại lọt (B3), `*_FILE` bị chặn nhầm (B7) | ◐ |
| | **NIST 800-190 §3.1.4** *Embedded clear text secrets* / §4.1.4 | Bí mật để ngoài image, cấp lúc chạy qua cơ chế quản lý bí mật | Đúng rủi ro này — **nên thêm vào trích dẫn** | ● |
| | **PCI-DSS 8.2.1** (theo **v3.2.1**) | v3.2.1: credential phải không đọc được khi lưu/truyền (mã hóa mạnh) | Ở **v4.0** đổi số: **8.3.2** (như trên) và **8.6.2** — mật khẩu tài khoản ứng dụng/hệ thống **không được ghi cứng** trong script, tệp cấu hình, mã nguồn → **8.6.2 khớp sát nhất** | ◐ |
| | **GDPR Đ.32(1)(b)** | Bảo đảm tính bí mật của hệ thống xử lý | Bí mật lộ → kẻ tấn công vào được dữ liệu cá nhân | ○ |

**c) `compose.rego` (F03) và `runtime.rego` — từng luật**

| Luật | Điều khoản | Điều khoản yêu cầu gì | Luật thực thi tới đâu | Khớp |
|---|---|---|---|:-:|
| F03 NET-02 — backend publish cổng | Luật **riêng của nhóm**; cơ sở: **GDPR Đ.25(2)**, **NIST 800-190 §3.4.2** *Unbounded network access* | 25(2): mặc định không để dữ liệu tiếp cận được bởi số người không xác định. §3.4.2: hạn chế lưu lượng mạng của container | Chỉ dịch vụ gắn nhãn `edge` (proxy) được có cổng host → `/metrics` chỉ đi qua proxy (proxy trả 404) | ● |
| NET-01 — bind ngoài `127.0.0.1` | **GDPR Đ.32**; (nên thêm) **CIS 5.13** *bind incoming container traffic to a specific host interface* | 5.13: cổng publish phải gắn vào một giao diện mạng cụ thể, không phải mọi giao diện | Đòi đúng `127.0.0.1` (chặt hơn CIS — CIS chỉ đòi "giao diện cụ thể") | ● |
| `privileged: true` / PRIV-01 | **CIS 5.4** *privileged containers are not used* | Container privileged có gần như mọi quyền của host | Cấm ở compose (trước triển khai) và trên container đang chạy | ● |
| Mount `docker.sock` | **CIS 5.31** *Docker socket is not mounted inside any containers* | Ai có socket là điều khiển được daemon → root host | Cấm ở compose | ● |
| Bí mật inline trong `environment` | PCI-DSS 8.2.1 (v4.0: **8.6.2**), GDPR Đ.32; **NIST 800-190 §4.1.4** | Như mục bí mật ở trên | Cho phép `*_FILE` (trỏ tới tệp secret) — làm đúng hơn luật Dockerfile | ◐ |
| Thiếu `cap_drop: [ALL]` (WARN) / PRIV-03 (FAIL) | **CIS 5.3** *Linux kernel capabilities are restricted* | Bỏ mọi capability không cần thiết | compose chỉ **nhắc**, runtime **chặn** — vì quyết định cuối nằm ở container thật | ◐ / ● |
| Thiếu `read_only` (WARN) | **CIS 5.12** *container's root filesystem is mounted as read only* | Root filesystem chỉ đọc, chỗ cần ghi dùng volume/tmpfs | Chỉ nhắc — backend Juice Shop cần ghi SQLite nên chưa bật | ◐ |
| PRIV-02 — UID số ≥ 1 | **CIS 4.1** (đúng phần *Audit* của mục này) | *Audit* của CIS 4.1 chính là xem `Config.User` của container đang chạy | Kiểm đúng chỗ CIS kiểm; chặt hơn lớp Dockerfile (`node` cũng FAIL) | ● |
| PRIV-04 — `no-new-privileges` | **CIS 5.25** *container is restricted from acquiring additional privileges* | Chặn leo quyền qua tệp setuid/setgid | Đòi `no-new-privileges:true` | ● |
| RES-02 — giới hạn CPU | **CIS 5.11** (CPU priority/shares), **NIST 800-190 §3.4.3** | Một container không được chiếm hết tài nguyên host | Đòi `NanoCpus > 0` (giới hạn cứng, chặt hơn "shares") | ● |
| RES-03 — giới hạn PID | **CIS 5.28** *PIDs cgroup limit is used* | Giới hạn số tiến trình → chống fork bomb | Đòi `PidsLimit > 0` | ● |

> `runtime.rego` hiện **không ghi điều khoản trong thông báo** (chỉ mã `PRIV-0x`, `RES-0x`, `NET-0x`); mapping ở bảng trên là tài liệu đối chiếu. `docker_security.rego` và `compose.rego` thì trích điều khoản ngay trong thông báo FAIL.

**d) Những trích dẫn nên chỉnh (nói chủ động nếu bị hỏi)**
- **PCI-DSS 8.2.1** là số mục của **v3.2.1**. Theo v4.0.1 hiện hành: **8.6.2** (không ghi cứng mật khẩu tài khoản ứng dụng/hệ thống) khớp sát nhất, kèm 8.3.2.
- **PCI-DSS 2.2** cho LEAST-PRIVILEGE chỉ khớp ở mức "cấu hình an toàn"; đặc quyền tối thiểu đúng nghĩa là **7.2.5**. ATTACK-SURFACE nên trích thêm **2.2.4** (chỉ bật dịch vụ cần thiết).
- **NET-01** đang chỉ trích GDPR; nên trích thêm **CIS 5.13**.
- **SECRET-IN-IMAGE** nên trích thêm **NIST 800-190 §3.1.4** — mục nói đúng rủi ro "bí mật dạng rõ trong image".
- **`:latest` / digest** ghi "CIS §4" là trích **chung**; CIS không có mục riêng — nói là *thực hành tốt*, đừng nói "CIS 4.x quy định".

### 14.5 Cùng một rủi ro, kiểm ở nhiều lớp

| Rủi ro | Dockerfile | Compose | Runtime |
|---|---|---|---|
| Chạy root | FAIL (root) / WARN (tên) | — | FAIL (chặt nhất) |
| Backend lộ cổng (F03) | — | FAIL | FAIL |
| Bind ngoài loopback | — | FAIL | FAIL |
| Privileged | — | FAIL | FAIL |
| Capability | — | WARN | FAIL |
| Bí mật nhúng sẵn | FAIL | FAIL | — |
| Cổng quản trị/CSDL | FAIL | — | — |
| Nguồn gốc / base image | FAIL / WARN | — | — |

### 14.6 Trạng thái hiện tại của repo (chạy thật)

- `conftest verify -p policy -p report/policy`: **26/26** (13 + 6 + 7). Chỉ `-p policy` thì 19/19 như ở mục 2.
- Dockerfile + hotfix: **0 FAIL**, 2 WARN — `node:24` và `distroless/nodejs24-debian13` chưa ghim digest (hotfix ghim rồi).
- Compose: **0 FAIL**, 1 WARN — `juice-shop` chưa `read_only`.
- Runtime: `juice-app-juice-shop-1` và `juice-app-proxy-1` đều **8/8**.

### 14.7 Chạy từng bộ luật bằng Docker (PowerShell, đứng ở gốc repo)

```powershell
docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 verify -p policy -p report/policy
docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test Dockerfile deploy/Dockerfile.hotfix --parser dockerfile -p policy --namespace dockerfile
docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test docker-compose.yml -p policy --namespace compose
docker inspect --format '{{json .}}' juice-app-juice-shop-1 | docker run --rm -i -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test --parser json -p report/policy --namespace runtime -
docker inspect --format '{{json .}}' juice-app-proxy-1     | docker run --rm -i -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test --parser json -p report/policy --namespace runtime -
```

Lỗi hay gặp:
- **Đường dẫn sau tên image là đường dẫn trong container Linux**: viết `report/fixtures/Dockerfile.vulnerable` (hoặc `/work/report/...`). `.\report\...` (dấu `\`) và `/report/...` (tuyệt đối từ gốc container) đều báo `no such file or directory`.
- **Thiếu `--namespace`** → Conftest chỉ chạy gói `main` → "0 tests".
- **Không ghi `docker inspect … > x.json` trong PowerShell 5.1** (ra UTF-16, Conftest đọc lỗi) → dùng pipe như trên. `docker inspect` 2 container một lần trả **mảng** — `runtime.rego` cần từng object, nên chạy riêng từng container.
- Git Bash: thay `${PWD}` bằng `$(pwd -W)` và thêm `MSYS_NO_PATHCONV=1` đầu lệnh.

### 14.8 Chưa bắt (tóm tắt mục 9)

Bí mật dưới tên vô hại (B3) · dải cổng `20-25` (B2) · `*_FILE` trong Dockerfile bị chặn nhầm (B7 — compose đã xử lý đúng) · `ARG …==x` (B10) · `USER ${ARG}` mặc định 0 (B5, lớp runtime chặn) · giới hạn RAM (RES-01 bỏ có chủ ý theo phạm vi báo cáo).
