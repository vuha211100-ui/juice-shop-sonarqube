// Nội dung 4 bộ slide — mỗi bộ phản ánh PHẦN VIỆC của một thành viên (không chỉ lỗi được giao).
// Nguồn: git diff v20.2.0..HEAD, TONG_KET_PHAN_CONG.md §2–§4, báo cáo .docx, các lần chạy thật 06–07/11.
const { buildDeck, fa, SHOT, NAVY, INK, MUTED, RED, GREEN } = require("./build.js");

// ======================= Thắng — B26CHAT039 =======================
const THANG = {
  file: "TV1_NguyenToanThang_B26CHAT039.pptx", color: "D9474F",
  member: "Nguyễn Toàn Thắng", mssv: "B26CHAT039",
  title: "Lớp mã nguồn: vá F01, SAST và kiểm thử bảo mật",
  subtitle: "Phần việc trong dự án Security as Code cho OWASP Juice Shop",
  pills: ["Pha: Code → Test", "Semgrep · node:test + Supertest", "Lỗi phụ trách: F01 SQL injection"],
  icons: { search: fa.FaSearch, flask: fa.FaFlask, filter: fa.FaFilter, code: fa.FaCode },
  slides: [
    { type: "cover" },
    { type: "compare", title: "Nhóm thêm vá, SAST, kiểm thử và cổng tự động",
      rows: [
        ["Đăng nhập", "login.ts ghép email vào chuỗi SQL — ' OR 1=1-- vượt xác thực", "Truy vấn tham số $email/$password, ép kiểu đầu vào về string"],
        ["Phân tích tĩnh", "CodeQL trong CI của dự án gốc, không gắn với F01–F04", "Semgrep với 2 bộ luật (owasp-top-ten, nodejsscan), quét routes/ + lib/, phân loại 38 cảnh báo"],
        ["Kiểm thử bảo mật", "Bộ test gốc coi SQLi đăng nhập là thử thách phải giải được", "11 ca F01/F02 đỏ trước vá, xanh sau vá; 2 ca SQLi trong bộ test gốc đổi sang 401"],
        ["Cổng pipeline", "Không có", "semgrep-diff.mjs chỉ chặn cảnh báo SAST mới; cổng Test chạy node:test ở push và CI"],
        ["Bằng chứng", "—", "Demo tv1 trên 3100/3102, khung demo dùng chung, script sinh hình đỏ/xanh"],
      ] },
    { type: "overview", title: "Năm đầu việc ở lớp mã nguồn",
      items: [
        ["Vá F01 bằng truy vấn tham số", "routes/login.ts", "5 payload SQLi: 200 → 401"],
        ["Dựng bước SAST với Semgrep", "report/semgrep-rules/", "38 cảnh báo / 25 tệp, khoanh đúng F01 và F02"],
        ["Khung kiểm thử bảo mật (TDS)", "test/api/security/f01-f02.test.ts", "đỏ 7/11 trước vá → xanh 11/11"],
        ["Cổng Code + Test trong pipeline", "devsecops/semgrep-diff.mjs", "SQLi quay lại bị chặn ngay khi commit"],
        ["Demo và hình bằng chứng", "demos/tv1, common.py, capture_demos.py", "log gốc kèm thời điểm và exit code"],
      ] },
    { type: "code2", kicker: "Việc 1 · Vá ứng dụng", title: "Vá login.ts: dữ liệu nhập không còn là mã SQL",
      before: "`SELECT * FROM Users\n WHERE email = '${req.body.email}'\n AND password = '${hash(pw)}'\n AND deletedAt IS NULL`",
      after: "const email = typeof req.body.email\n  === 'string' ? req.body.email : ''\nmodels.sequelize.query(\n  'SELECT * FROM Users\n   WHERE email = $email\n   AND password = $password\n   AND deletedAt IS NULL',\n  { bind: { email,\n      password: security.hash(password) },\n    model: UserModel, plain: true })",
      why: [
        "Trước: email ' OR 1=1-- biến WHERE thành luôn đúng, -- đẩy phần mật khẩu thành chú thích → cấp JWT admin.",
        "Sau: câu lệnh và giá trị đi riêng, ' và -- chỉ còn là ký tự; ép kiểu string chặn kiểu lách gửi object.",
        "Vẫn băm mật khẩu trước khi so — kiểm thử bắt được lỗi \"vá quá tay\" nếu quên security.hash.",
      ] },
    { type: "shotcards", kicker: "Việc 2 · SAST", title: "Dựng bước SAST: Semgrep quét toàn bộ mã chưa vá",
      shot: "semgrep-overview.png", caption: "Semgrep 1.180.0 trên routes/ + lib/ chưa vá: 38 cảnh báo / 25 tệp — F01 tại login.ts, F02 tại fileServer.ts",
      cards: [
        ["Chọn và ghim bộ luật", "owasp-top-ten + nodejsscan lưu trong repo (report/semgrep-rules/), chạy qua Docker image ghim phiên bản — ai chạy cũng ra cùng kết quả.", "search"],
        ["Phân loại kết quả", "38 là cảnh báo công cụ, chưa phải 38 lỗ hổng. Trong phạm vi báo cáo xác nhận 2 điểm: express-sequelize-injection (F01), express-res-sendfile (F02).", "filter"],
      ] },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 3 · Test-Driven Security", "Khung kiểm thử bảo mật: đỏ khi còn lỗi, xanh sau khi vá");
      const a = await H.picture(s, SHOT("f0102-red.png"), 0.6, 1.6, 5.9, 2.6, "Kiểm thử trước vá");
      H.caption(s, "Mã chưa vá: 4 đạt, 7 đỏ (5 ca SQLi, 2 ca null byte)", 0.6, 1.6 + a.h + 0.08, 5.9);
      const b = await H.picture(s, SHOT("f0102-green.png"), 6.8, 1.6, 5.9, 2.6, "Kiểm thử sau vá");
      H.caption(s, "Sau vá: 11/11 ca đạt", 6.8, 1.6 + b.h + 0.08, 5.9);
      H.card(s, { x: 0.6, y: 4.5, w: 5.9, h: 2.25, head: "Cách dựng", ico: H.I.flask,
        body: "node:test + Supertest gọi thẳng app trong tiến trình, không cần mở cổng. Mỗi payload SQLi kèm mật khẩu sai phải nhận 401; đăng nhập đúng vẫn phải nhận token." });
      H.card(s, { x: 6.8, y: 4.5, w: 5.9, h: 2.25, head: "Vì sao cần ngoài Semgrep", ico: H.I.code,
        body: "SAST chỉ nói \"dòng này đáng ngờ\"; kiểm thử chứng minh khai thác được, và bắt lỗi mà SAST bỏ sót (F02) hoặc vá sai (quên băm mật khẩu)." });
    } },
    { type: "gates", kicker: "Việc 4 · Cổng trong pipeline", title: "Đưa Semgrep và kiểm thử thành cổng tự động",
      phases: ["Code", "Test"],
      cols: [
        { when: "git commit", blocked: true, result: "Commit bị hủy", body: "Đưa lại login.ts chưa vá: Semgrep báo 1 cảnh báo MỚI express-sequelize-injection → FAIL (chạy thật 07/11)." },
        { when: "git push", blocked: true, result: "Push bị hủy", body: "Commit bằng --no-verify thì pre-push chạy lại Semgrep; qua được Code thì cổng Test có 5 ca SQLi đỏ." },
        { when: "GitHub Actions", blocked: true, result: "Step Code đỏ", body: "Bỏ qua cả hai hook, workflow vẫn chạy cùng cổng trên GitHub." },
      ],
      note: "semgrep-diff.mjs so cảnh báo của bản mới với bản gốc của cùng tệp, nhận diện theo luật + nội dung dòng (không theo số dòng) — 38 cảnh báo có sẵn của Juice Shop không chặn mọi thay đổi về sau." },
    { type: "shotstats", kicker: "Việc 5 · Demo và bằng chứng", title: "Demo trước/sau vá trên hai môi trường đối chứng",
      shot: "tv1.png", cmd: "python report/demos/tv1_f01_sqli.py   ·   log: report/evidence/tv1-f01.log",
      stats: [["5/5", "payload trước vá (3100): 200 + token", RED], ["401", "sau vá (3102): cả 5 payload bị từ chối", GREEN],
        ["200", "đăng nhập hợp lệ vẫn hoạt động"], ["11/11", "ca kiểm thử bảo mật xanh"]] },
    { type: "files", title: "Những gì đã thêm vào kho mã",
      rows: [
        ["Vá F01: truy vấn tham số, ép kiểu string", "routes/login.ts"],
        ["Bộ luật SAST dùng trong báo cáo và pipeline", "report/semgrep-rules/"],
        ["11 ca kiểm thử bảo mật F01/F02", "test/api/security/f01-f02.test.ts"],
        ["2 ca SQLi của bộ test gốc → kỳ vọng 401", "test/api/login.test.ts"],
        ["Cổng Semgrep chỉ chặn cảnh báo mới", "devsecops/semgrep-diff.mjs"],
        ["Demo F01 + khung demo dùng chung", "report/demos/tv1_f01_sqli.py, common.py"],
        ["Sinh hình đỏ/xanh, tv1–tv4", "report/figures/capture_demos.py"],
      ],
      tools: [["Semgrep 1.180.0", "Pha 3 · SAST · cổng Code"], ["node:test + Supertest", "Pha 4 · TDS · cổng Test"], ["TypeScript / Express", "Pha 5 · vá ứng dụng"]] },
    { type: "end", headline: "Lớp mã nguồn có ba lớp chặn: vá đúng chỗ, SAST tìm sớm, kiểm thử giữ lại",
      done: ["Vá login.ts; đăng nhập hợp lệ không đổi", "Dựng SAST + khung kiểm thử 11 ca dùng chung cho F01, F02", "Semgrep và kiểm thử thành cổng commit, push, CI"],
      limits: ["Semgrep còn báo express-sequelize-injection ở routes/search.ts — ngoài phạm vi", "38 cảnh báo SAST mới được phân loại, chưa rà hết", "Cổng Test vẫn qua nếu ai đó xóa hết ca kiểm thử"],
      next: ["Rà và vá search.ts cùng các NoSQL injection còn lại", "Bắt buộc tối thiểu 11 ca kiểm thử trong cổng Test", "Ưu tiên query builder của ORM thay SQL thô"] },
  ],
};

// ======================= Thúy — B26CHAT042 =======================
const THUY = {
  file: "TV2_PhamThiMinhThuy_B26CHAT042.pptx", color: "C9820F",
  member: "Phạm Thị Minh Thúy", mssv: "B26CHAT042",
  title: "Lớp tệp và chuỗi cung ứng: vá F02, secret, dependency",
  subtitle: "Phần việc trong dự án Security as Code cho OWASP Juice Shop",
  pills: ["Pha: Code → Test → Release", "Gitleaks · Trivy · node:test", "Lỗi phụ trách: F02 Poison Null Byte"],
  icons: { key: fa.FaKey, box: fa.FaBoxOpen, list: fa.FaListAlt, flask: fa.FaFlask, search: fa.FaSearch },
  slides: [
    { type: "cover" },
    { type: "compare", title: "Bản gốc chưa có cổng secret và CVE gắn với commit",
      rows: [
        ["Phục vụ tệp /ftp", "fileServer.ts kiểm đuôi .md rồi mới cắt %00 → đọc được tệp .bak", "Từ chối %00 / ký tự NUL trước mọi bước kiểm tra → 403"],
        ["Kiểm thử F02", "Không có ca cho null byte", "Ca …bak%2500.md phải 403, legal.md vẫn 200"],
        ["Quét secret", "Không có cổng quét secret cho commit của nhóm", "Gitleaks + .gitleaks.toml: 42 commit, no leaks; cổng chỉ quét dòng được thêm"],
        ["Quét dependency (SCA)", "Sinh SBOM CycloneDX, không quét CVE trong luồng", "Trivy quét image: 173 CVE; .trivyignore 11 CVE chấp nhận → chỉ chặn CRITICAL mới"],
        ["Bằng chứng", "—", "Demo tv2; script sinh hình Trivy, Dockle, giám sát"],
      ] },
    { type: "overview", title: "Năm đầu việc ở lớp tệp và chuỗi cung ứng",
      items: [
        ["Vá F02: từ chối null byte", "routes/fileServer.ts", "payload …%2500.md: 200 → 403"],
        ["Ca kiểm thử F02", "test/api/security/f01-f02.test.ts", "2 ca đỏ → xanh; legal.md vẫn 200"],
        ["Quét secret bằng Gitleaks", ".gitleaks.toml", "0 leak / 42 commit; khóa mới bị chặn"],
        ["SCA bằng Trivy", "devsecops/.trivyignore", "173 CVE; cổng chỉ chặn CRITICAL mới"],
        ["Demo và hình bằng chứng", "demos/tv2, figures/capture_scans.py", "log gốc kèm exit code"],
      ] },
    { type: "code2", kicker: "Việc 1 · Vá ứng dụng", title: "Vá fileServer.ts: từ chối null byte trước khi kiểm tra",
      before: "if (file && (endsWithAllowlistedFileType(file)\n    || ...)) {\n  file = security.cutOffPoisonNullByte(file)\n  res.sendFile(path.resolve('ftp/', file))\n}",
      after: "if (file && (file.includes('%00')\n    || file.includes('\\u0000'))) {\n  res.status(403)\n  next(new Error(\n    'File names cannot contain null bytes!'))\n  return\n}\n// sau đó mới kiểm đuôi .md/.pdf và phục vụ",
      why: [
        "Trước: …bak%2500.md giải mã thành …bak%00.md, qua bộ lọc .md, rồi bị cắt thành package.json.bak và gửi đi.",
        "Sau: tên chứa %00 hay NUL bị từ chối ngay (403) — giá trị được kiểm chính là giá trị được phục vụ.",
        "Tệp hợp lệ không bị ảnh hưởng: legal.md vẫn trả 200.",
      ] },
    { type: "gates", kicker: "Việc 2 · Ca kiểm thử F02", title: "Ca kiểm thử là lưới chặn duy nhất cho lỗi này",
      phases: ["Code", "Test"],
      cols: [
        { when: "git commit", blocked: false, result: "Commit đi qua", body: "Đưa lại fileServer.ts chưa vá: Semgrep PASS — cảnh báo res.sendFile đã có từ bản gốc, SAST không hiểu null byte." },
        { when: "git push", blocked: true, result: "Push bị hủy", body: "pre-push chạy node:test: ca null byte nhận 200 thay vì 403 → Test FAIL, các pha sau SKIP (chạy thật 07/11)." },
        { when: "GitHub Actions", blocked: true, result: "Cùng cổng Test", body: "Workflow gọi cùng pipeline.sh, nên bỏ qua hook vẫn gặp đúng cổng Test." },
      ],
      note: "Hai ca kiểm thử của F02: GET /ftp/package.json.bak%2500.md và coupons_2013.md.bak%2500.md phải nhận 403; GET /ftp/legal.md vẫn phải nhận 200 — chống vá quá tay." },
    { type: "shotcards", kicker: "Việc 3 · Quét secret", title: "Gitleaks: chặn secret mới, không báo nhầm khóa giả của demo",
      shot: "gitleaks.png", wide: true, maxH: 2.2, caption: "Gitleaks v8.30.1 trên các commit vá của nhóm (baf9dcea4..HEAD): 42 commit, no leaks, exit 0",
      cards: [
        ["Chỉ quét dòng được thêm", "Juice Shop cố ý chứa secret; cổng chỉ xét phần nhóm thêm (pre-commit: phần đã git add; push/CI: các commit mới).", "key"],
        ["Allowlist hẹp, có lý do", "Chỉ bỏ qua khóa RSA giả của demo Dockle và đúng dòng lệnh demo trong tài liệu; ghi khóa AWS giả vào login.ts thật vẫn bị chặn.", "list"],
      ] },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 4 · SCA", "Trivy quét CVE dependency và danh sách rủi ro chấp nhận");
      const p = await H.picture(s, SHOT("trivy.png"), 0.6, 1.6, 7.3, 2.6, "Trivy quét image");
      H.caption(s, "Trivy 0.76.1 trên juice-shop:hotfix-f01-f02 — lớp SCA mà Semgrep và Conftest không phủ", 0.6, 1.6 + p.h + 0.08, 7.3);
      H.codeBlock(s, "devsecops/.trivyignore", "C9820F",
        "# 11 CVE CRITICAL có sẵn của image gốc\n# jsonwebtoken@0.1.0, 0.4.0 (fix 4.2.2)\nCVE-2015-9235\n# lodash@2.4.2 (fix 4.17.12)\nCVE-2019-10744\n# crypto-js@3.3.0 (fix 4.2.0)\nCVE-2023-46233\n…", 0.6, 4.55, 7.3, 2.2, 12);
      H.stat(s, "173", "CVE duy nhất trong image (189 bản ghi)", 8.2, 1.6, 4.5, RED);
      H.stat(s, "12", "CRITICAL · 56 HIGH · 97 MEDIUM · 24 LOW", 8.2, 3.25, 4.5);
      H.card(s, { x: 8.2, y: 4.9, w: 4.5, h: 1.85, head: "Cổng Release", ico: H.I.box,
        body: "Chỉ chặn CVE CRITICAL không nằm trong danh sách — tức khi thay đổi kéo thêm thư viện có lỗi." });
    } },
    { type: "shotstats", kicker: "Việc 5 · Demo và bằng chứng", title: "Demo trước/sau vá trên hai môi trường đối chứng",
      shot: "tv2.png", cmd: "python report/demos/tv2_f02_pathtraversal.py   ·   log: report/evidence/tv2-f02.log",
      stats: [["200", "trước vá: đọc được cả 2 tệp .bak", RED], ["403", "sau vá: cả 2 payload bị từ chối", GREEN],
        ["200", "legal.md hợp lệ vẫn tải được"], ["0", "leak trên 42 commit của nhóm"]] },
    { type: "files", title: "Những gì đã thêm vào kho mã",
      rows: [
        ["Vá F02: từ chối %00/NUL trước bước kiểm đuôi", "routes/fileServer.ts"],
        ["Ca kiểm thử F02 (null byte → 403, .md hợp lệ → 200)", "test/api/security/f01-f02.test.ts"],
        ["Cấu hình Gitleaks, allowlist khóa giả của demo", ".gitleaks.toml"],
        ["Danh sách rủi ro chấp nhận cho cổng Trivy", "devsecops/.trivyignore"],
        ["Kết quả quét CVE đầy đủ", "report/evidence/trivy-image.json"],
        ["Demo F02", "report/demos/tv2_f02_pathtraversal.py"],
        ["Sinh hình Trivy, Dockle, giám sát", "report/figures/capture_scans.py"],
      ],
      tools: [["Trivy 0.76.1", "Pha 3 · SCA · cổng Release"], ["node:test + Supertest", "Pha 4 · ca kiểm thử F02"], ["TypeScript / Express", "Pha 5 · vá ứng dụng"], ["Gitleaks v8.30.1", "Pha 7 · quét secret · cổng Code"]] },
    { type: "end", headline: "Từ một route tệp đến chuỗi cung ứng: vá, kiểm thử, quét secret và dependency",
      done: ["Vá fileServer.ts; ca kiểm thử F02 xanh", "Gitleaks 0 leak / 42 commit, khóa mới bị chặn", "Trivy lập danh sách 173 CVE; cổng chỉ chặn CRITICAL mới"],
      limits: ["Hóa đơn trong /ftp chưa kiểm JWT và chủ sở hữu đơn", "/ftp vẫn liệt kê thư mục; tệp .bak vẫn nằm trong ftp/", "12 CVE CRITICAL của image gốc mới ghi nhận, chưa nâng cấp"],
      next: ["Đưa hóa đơn ra sau kiểm tra JWT + chủ sở hữu đơn", "Tắt liệt kê thư mục, dọn tệp sao lưu khỏi ftp/", "Nâng cấp dependency CRITICAL (crypto-js, jsonwebtoken…)"] },
  ],
};

// ======================= Quốc Anh — B26CHAT001 =======================
const QUOCANH = {
  file: "TV3_DoDucQuocAnh_B26CHAT001.pptx", color: "33729E",
  member: "Đỗ Đức Quốc Anh", mssv: "B26CHAT001",
  title: "Hạ tầng triển khai, vận hành và CI",
  subtitle: "Phần việc trong dự án Security as Code cho OWASP Juice Shop",
  pills: ["Pha: Deploy → Operate → Monitor", "Compose · nginx · Prometheus · Actions", "Lỗi phụ trách: F03 /metrics"],
  icons: { server: fa.FaServer, bell: fa.FaBell, git: fa.FaCodeBranch, shield: fa.FaShieldAlt, archive: fa.FaArchive },
  slides: [
    { type: "cover" },
    { type: "compare", title: "Bản gốc bỏ trống kiến trúc triển khai an toàn",
      rows: [
        ["Triển khai", "Chỉ docker run; thư mục infrastructure/ cố tình viết lỗi", "docker-compose: mạng edge + backend internal; 2 môi trường đối chứng 3100 / 3102"],
        ["Reverse proxy", "Không có", "nginx: /metrics 404, đăng nhập 5 lần/phút → 429, header bảo mật, log không chứa dữ liệu cá nhân"],
        ["Gia cố container", "Chỉ chạy non-root", "cap_drop ALL, no-new-privileges, giới hạn CPU/PID, tmpfs noexec, proxy read_only"],
        ["Policy as Code triển khai", "Không có", "compose.rego: chỉ dịch vụ edge được mở cổng host — 6 ca kiểm thử"],
        ["Giám sát", "/metrics mở cho tất cả; không Prometheus", "Prometheus scrape nội bộ, cảnh báo HighClientErrorRate, Grafana"],
        ["CI", "16 workflow gốc, không gắn F01–F04", "devsecops.yml: mỗi pha một step, chạy xanh đủ 7 pha"],
      ] },
    { type: "overview", title: "Sáu đầu việc ở hạ tầng và vận hành",
      items: [
        ["Topology 2 mạng, 2 môi trường", "docker-compose.yml", "backend 0 cổng host"],
        ["Reverse proxy nginx", "deploy/nginx.conf, proxy-start.sh", "/metrics 404 · đăng nhập 429"],
        ["Policy as Code cho compose", "policy/compose.rego", "6/6 ca; cấu hình trước vá exit 1"],
        ["Kiểm container đang chạy", "report/checks/hardening.py", "3 container non-root, cap_drop ALL"],
        ["Giám sát + cảnh báo", "docker-compose.monitoring.yml", "target UP · cảnh báo FIRING thật"],
        ["GitHub Actions", ".github/workflows/devsecops.yml", "đủ 7 pha xanh trên GitHub"],
      ] },
    { type: "code2", kicker: "Việc 1–2 · Topology và proxy", title: "Chỉ proxy được mở cổng; backend nằm trong mạng internal",
      beforeLabel: "docker-compose.yml", beforeColor: "33729E", afterLabel: "deploy/nginx.conf", afterColor: "33729E", whyHead: "Kết quả",
      before: "proxy:\n  ports: [\"127.0.0.1:3102:8080\"]\n  labels: {lab.exposure: edge}\n  read_only: true\njuice-shop:\n  labels: {lab.exposure: internal}\n  # không có khóa ports\n  user: \"65532:0\"\n  cap_drop: [ALL]\nnetworks:\n  backend: {internal: true}",
      after: "server_tokens off;\nadd_header X-Content-Type-Options\n  nosniff always;\nlocation = /metrics { return 404; }\nlocation = /rest/user/login {\n  limit_req zone=login burst=5 nodelay;\n  limit_req_status 429;\n  proxy_pass http://juice-shop:3000;\n}",
      why: [
        "Backend không còn cổng host: mọi request phải qua proxy — /metrics → 404, đăng nhập quá 5 lần/phút → 429.",
        "Mạng backend internal, không có đường ra ngoài; Prometheus vẫn đọc /metrics trong mạng nội bộ.",
        "Log proxy dạng JSON chỉ ghi route đã chuẩn hóa, không ghi query string; proxy-start.sh xoay vòng log.",
      ] },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 3 · Policy as Code", "compose.rego: chỉ dịch vụ biên được mở cổng host");
      H.codeBlock(s, "LUẬT F03 NET-02", "33729E", "edge(svc) if object.get(object.get(svc,\n  \"labels\", {}), \"lab.exposure\", \"\") == \"edge\"\n\ndeny contains msg if {\n  some name, svc in input.services\n  count(ports(svc)) > 0  # có cổng host\n  not edge(svc)          # không phải biên\n  msg := sprintf(\"[F03 NET-02] ...\", [name])\n}", 0.6, 1.6, 6.3, 3.5);
      const rows = [H.head(["Luật", "Yêu cầu", "Mức"]),
        ...[["F03 NET-02", "Không phải edge thì không publish cổng host — kể cả loopback", "FAIL"],
          ["NET-01", "Cổng đã publish phải bind 127.0.0.1", "FAIL"], ["CIS 5.4 · 5.31", "Không privileged, không mount docker.sock", "FAIL"],
          ["INLINE-SECRET", "Không đặt mật khẩu/token trong environment", "FAIL"], ["CIS 5.3 · 5.12", "Nên cap_drop ALL và read_only", "WARN"]]
          .map((r) => r.map((t, j) => ({ text: t, options: { bold: j !== 1, color: j === 0 ? "33729E" : j === 2 ? (t === "FAIL" ? RED : "C9820F") : INK } })))];
      s.addTable(rows, { x: 7.2, y: 1.6, w: 5.5, colW: [1.55, 3.2, 0.75], fontSize: 13, fontFace: "Calibri",
        border: { type: "solid", pt: 0.75, color: "D5DCE6" }, valign: "middle", margin: [0.05, 0.08, 0.05, 0.08], rowH: 0.5 });
      H.stats(s, [["6/6", "ca kiểm thử compose_test.rego"], ["exit 1", "compose trước vá: đúng 1 FAIL F03 NET-02", RED], ["exit 0", "docker-compose.yml sau vá", GREEN]], 5.35);
    } },
    { type: "shotstats", kicker: "Việc 4 · Compliance as Code", title: "hardening.py kiểm cấu hình trên container đang chạy",
      shot: "hardening.png", cmd: "python report/checks/hardening.py   ·   log: report/evidence/hardening.log",
      stats: [["0", "cổng host của backend (docker inspect)", GREEN], ["3/3", "container non-root, cap_drop ALL, no-new-privileges"],
        ["true", "mạng juice-app_backend là internal"], ["127.0.0.1", "proxy chỉ mở loopback 3102"]] },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 5 · Giám sát vận hành", "/metrics chặn ra ngoài nhưng vẫn là nguồn giám sát nội bộ");
      const p = await H.picture(s, SHOT("grafana-dashboard.png"), 0.6, 1.6, 6.6, 4.65, "Dashboard Grafana");
      H.caption(s, "Grafana: người dùng, đơn hàng, HTTP theo status_code — số liệu thật từ ứng dụng đang chạy", 0.6, 1.6 + p.h + 0.08, 6.6);
      await H.picture(s, SHOT("monitoring.png"), 7.5, 1.6, 5.2, 1.0, "Prometheus và cảnh báo");
      H.card(s, { x: 7.5, y: 2.75, w: 5.2, h: 1.85, head: "Prometheus scrape nội bộ", ico: H.I.server,
        body: "Đọc juice-app-juice-shop-1:3000/metrics qua mạng backend — target UP, không cần mở cổng host." });
      H.card(s, { x: 7.5, y: 4.8, w: 5.2, h: 1.95, head: "Cảnh báo HighClientErrorRate", ico: H.I.bell,
        body: "4XX > 20 trong 2 phút → FIRING. Mô phỏng 60 lần đăng nhập sai: cảnh báo kích hoạt thật." });
    } },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 6 · CI", "GitHub Actions chạy đủ 7 pha, mỗi pha một step");
      H.codeBlock(s, ".github/workflows/devsecops.yml", "33729E",
        "on: push (main, fix/**, tv-*), pull_request,\n    workflow_dispatch (full)\nsteps:\n  Plan    · checkout + xác định commit gốc\n  Code    · Gitleaks + Semgrep\n          · npm install --before 1 ngày\n  Build   · Conftest + tsc + docker build\n  Test    · node:test + Supertest\n  Release · Trivy + Dockle → gắn tag\n  Deploy  · compose.rego + compose up\n  Operate · runtime.rego + kiểm proxy\n  Monitor · Prometheus + cảnh báo\n  Lưu log làm artifact · dọn môi trường", 0.6, 1.6, 6.5, 5.15, 13);
      H.card(s, { x: 7.4, y: 1.6, w: 5.3, h: 1.6, head: "Không bỏ qua được", ico: H.I.git,
        body: "Hook trên máy có thể né bằng --no-verify; workflow là cổng cuối cùng chạy cùng pipeline.sh trên runner sạch." });
      H.card(s, { x: 7.4, y: 3.45, w: 5.3, h: 1.6, head: "Cài đặt ổn định", ico: H.I.archive,
        body: "Không có lockfile → npm install --before 1 ngày, tránh lỗi ERESOLVE khi bộ gói Angular đang phát hành dở." });
      H.stat(s, "4 phút 49", "run 42283870461: đủ 7 pha, tất cả step xanh", 7.4, 5.3, 5.3, GREEN);
    } },
    { type: "gates", kicker: "Kiểm chứng tích hợp", title: "Cấu hình sai quay lại — chặn ở Deploy và Operate",
      phases: ["Deploy", "Operate", "Monitor"],
      cols: [
        { when: "git commit", blocked: true, result: "Commit bị hủy", body: "Mở lại cổng backend 0.0.0.0:3000 → compose.rego báo F03 NET-02 + NET-01 ngay ở pre-commit." },
        { when: "git push", blocked: true, result: "Push bị hủy", body: "Bỏ dòng chặn /metrics trong nginx.conf: commit qua; pre-push triển khai lên 3102, Operate gọi /metrics → 200 → FAIL." },
        { when: "GitHub Actions", blocked: false, result: "Kiểm lại trên runner", body: "Triển khai thật rồi kiểm /metrics 404, header, 429, Prometheus target UP và luật cảnh báo." },
      ],
      note: "Policy as Code chặn cấu hình sai nằm trong file; kiểm tra sau triển khai bắt cấu hình sai chỉ lộ khi chạy (không luật Rego nào đọc nginx.conf). Cả hai kịch bản đã chạy thật ngày 07/11." },
    { type: "files", title: "Những gì đã thêm vào kho mã",
      rows: [
        ["Topology 2 mạng, gia cố container", "docker-compose.yml"],
        ["Reverse proxy, xoay vòng log", "deploy/nginx.conf, deploy/proxy-start.sh"],
        ["Policy as Code + 6 ca kiểm thử, fixture trước vá", "policy/compose.rego, report/fixtures/"],
        ["Kiểm container đang chạy", "report/checks/hardening.py"],
        ["Stack giám sát, luật cảnh báo, dashboard", "docker-compose.monitoring.yml, deploy/monitoring/"],
        ["Workflow CI đủ 7 pha", ".github/workflows/devsecops.yml"],
        ["Demo F03", "report/demos/tv3_f03_metrics.py"],
      ],
      tools: [["Docker Compose", "Pha 1 · môi trường · Deploy"], ["Conftest compose.rego", "Pha 2 · Policy as Code"], ["docker inspect", "Pha 6 · Compliance as Code"], ["Prometheus · Grafana", "Pha 7 · Monitor"]] },
    { type: "end", headline: "Hạ tầng an toàn theo mặc định — và được kiểm lại tự động sau mỗi lần triển khai",
      done: ["Topology 2 mạng + proxy: /metrics 404, đăng nhập 429", "compose.rego, hardening.py, giám sát + cảnh báo FIRING", "GitHub Actions chạy xanh đủ 7 pha"],
      limits: ["Stack giám sát vi phạm chính compose.rego: Prometheus, Grafana mở cổng không phải edge", "Grafana ẩn danh quyền Admin; image :latest chưa ghim", "main chưa bật branch protection; proxy chưa có TLS"],
      next: ["Đưa Prometheus/Grafana ra sau proxy, ghim digest", "Bật branch protection bắt buộc job DevSecOps", "Alertmanager định tuyến cảnh báo; TLS khi mở ra ngoài"] },
  ],
};

// ======================= Vũ — B26CHAT048 =======================
const VU = {
  file: "TV4_HoAnhVu_B26CHAT048.pptx", color: "6C55C2",
  member: "Hồ Anh Vũ", mssv: "B26CHAT048",
  title: "Build & Release: Policy as Code và pipeline DevSecOps",
  subtitle: "Phần việc trong dự án Security as Code cho OWASP Juice Shop",
  pills: ["Pha: Build → Release", "Conftest · Dockle · Git hook", "Lỗi phụ trách: F04 cấu hình container"],
  icons: { box: fa.FaBox, server: fa.FaServer, file: fa.FaFileAlt, book: fa.FaBook, camera: fa.FaCamera },
  slides: [
    { type: "cover" },
    { type: "compare", title: "Nhóm thêm luật, image vá và quy trình Git",
      rows: [
        ["Image triển khai", "Image distroless, đã chạy non-root", "Dockerfile.hotfix: ghim digest, chỉ chép 2 route đã vá, USER 65532, nhãn OCI có commit, HEALTHCHECK"],
        ["Policy as Code cho image", "Không có", "docker_security.rego 4 nhóm luật, 13 ca kiểm thử; fixture lỗi bị chặn, bản tốt đạt"],
        ["Compliance as Code", "Không có", "Dockle (CIS image) + runtime.rego 8 luật trên docker inspect, 7 ca kiểm thử"],
        ["Quy trình Git", "Không có hook", "pipeline.sh 7 pha; pre-commit chạy cổng tĩnh, pre-push chạy đủ 7 pha và triển khai 3102"],
        ["Tài liệu", "—", "Báo cáo DOCX/PDF dựng từ một nguồn, sơ đồ quy trình, kịch bản tích hợp, slide"],
      ] },
    { type: "overview", title: "Sáu đầu việc ở Build, Release và quy trình",
      items: [
        ["Bộ luật Dockerfile", "policy/docker_security.rego", "13 ca; fixture lỗi exit 1"],
        ["Image đã vá", "deploy/Dockerfile.hotfix", "0 FAIL, 0 WARN; Dockle sạch"],
        ["Dockle + luật runtime", "report/policy/runtime.rego", "26/26 ca kiểm thử của 3 bộ luật"],
        ["Pipeline 7 pha", "devsecops/pipeline.sh", "push bản vá: 21 PASS · 0 FAIL"],
        ["Git hook + kịch bản tích hợp", ".githooks/, report/scanSAC.md", "commit/push lỗi bị hủy (chạy thật)"],
        ["Báo cáo và tài liệu", "report/tools/, report/slide/", "DOCX + PDF + slide từ một nguồn"],
      ] },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 1 · Policy as Code", "docker_security.rego: 4 nhóm, 8 luật chặn, 2 cảnh báo");
      const rows = [H.head(["Nhóm", "Bắt khi", "Mức"]),
        ...[["LEAST-PRIVILEGE", "Stage cuối không có USER · USER cuối là root (root, 0, 0:1000, root:1000)", "FAIL"],
          ["", "USER không phải UID số (vd USER node)", "WARN"],
          ["ATTACK-SURFACE", "EXPOSE 22, 23, 2375, 2376, 3306, 5432, 6379, 27017 — cả dạng 22/tcp, ở mọi stage", "FAIL"],
          ["SUPPLY-CHAIN", "Thiếu nhãn source/revision · FROM …:latest · dùng ADD", "FAIL"],
          ["", "FROM chưa ghim @sha256 digest", "WARN"],
          ["SECRET-IN-IMAGE", "ENV/ARG có tên như password, secret, token, api_key… kèm giá trị", "FAIL"]]
          .map((r) => r.map((t, j) => ({ text: t, options: { bold: j !== 1, color: j === 0 ? "6C55C2" : j === 2 ? (t === "FAIL" ? RED : "C9820F") : INK } })))];
      s.addTable(rows, { x: 0.6, y: 1.6, w: 12.1, colW: [2.5, 8.6, 1.0], fontSize: 14, fontFace: "Calibri",
        border: { type: "solid", pt: 0.75, color: "D5DCE6" }, valign: "middle", margin: [0.05, 0.1, 0.05, 0.1], rowH: 0.46 });
      H.stats(s, [["6", "vi phạm / 4 nhóm trên fixture lỗi → exit 1", RED], ["13", "ca kiểm thử, gồm các kiểu lách đã biết"], ["3", "Dockerfile tốt đều đạt: bản vá, gốc, hotfix", GREEN]], 5.3);
    } },
    { type: "code2", kicker: "Việc 2 · Image đã vá", title: "Dockerfile.hotfix: image triển khai đạt bộ luật sạch hoàn toàn",
      beforeLabel: "FIXTURE LỖI", afterLabel: "deploy/Dockerfile.hotfix",
      before: "FROM node:22-alpine\nCOPY . .\nENV API_TOKEN=supersecret123\nEXPOSE 3000 22 3306\nCMD [\"npm\", \"start\"]\n# không USER, không LABEL",
      after: "FROM bkimminich/juice-shop@sha256:8739…\nARG VCS_REF=fix-f01-f04\nLABEL org.opencontainers.image.source=…\\\n  org.opencontainers.image.revision=${VCS_REF}\nCOPY routes/login.js routes/fileServer.js \\\n     /juice-shop/build/routes/\nUSER 65532\nHEALTHCHECK … node -e \"http.get(…:3000/)\"",
      why: [
        "Ghim digest image gốc: image build hôm nay giống hệt image đã kiểm; chỉ chép đè đúng 2 route đã vá F01/F02.",
        "Nhãn revision nhận mã commit thật do pipeline truyền vào → từ container đang chạy lần ra đúng commit.",
        "USER 65532, không ENV bí mật, không cổng thừa — 0 FAIL, 0 WARN; Dockle không FATAL/WARN.",
      ] },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 3 · Compliance as Code", "Dockle soi image thành phẩm, runtime.rego soi container");
      const p = await H.picture(s, SHOT("dockle.png"), 0.6, 1.6, 6.6, 4.7, "Dockle quét image");
      H.caption(s, "Dockle 0.4.15: image đóng gói sai → FATAL CIS-DI-0010 + WARN CIS-DI-0001; image triển khai → không FATAL/WARN", 0.6, 1.6 + p.h + 0.08, 6.6);
      H.card(s, { x: 7.5, y: 1.6, w: 5.2, h: 2.45, head: "Dockle — pha Release", ico: H.I.box,
        body: "Đọc image đã build nên thấy secret trong tệp bị COPY (id_rsa giả) mà luật đọc Dockerfile không thấy. Có WARN/FATAL là không gắn tag phát hành." });
      H.card(s, { x: 7.5, y: 4.3, w: 5.2, h: 2.45, head: "runtime.rego — pha Operate", ico: H.I.server,
        body: "8 luật trên docker inspect: privileged, UID ≥ 1, cap_drop ALL, no-new-privileges, giới hạn CPU/PID, cổng host. App + proxy đạt 8/8." });
    } },
    { type: "custom", fn: async (H) => {
      const s = H.content("Việc 4 · Điều phối pipeline", "pipeline.sh: một script, 7 pha, dùng chung cho hook và CI");
      const rows = [H.head(["Pha", "Cổng", "Chặn khi"]),
        ...[["Code", "Gitleaks · Semgrep (chỉ cảnh báo mới)", "secret mới, cảnh báo SAST mới"],
          ["Build", "conftest verify · docker_security.rego · tsc · docker build", "luật sai, Dockerfile sai, lỗi biên dịch"],
          ["Test", "node:test + Supertest", "ca kiểm thử bảo mật đỏ"],
          ["Release", "Trivy · Dockle → gắn tag hotfix-f01-f02", "CVE CRITICAL mới, CIS WARN/FATAL"],
          ["Deploy", "compose.rego · docker compose up --wait", "compose sai, container không healthy"],
          ["Operate", "runtime.rego · /metrics 404 · header · 429", "container chạy sai, proxy hết chặn"],
          ["Monitor", "Prometheus target · luật cảnh báo", "không scrape được, thiếu luật"]]
          .map((r) => r.map((t, j) => ({ text: t, options: { bold: j === 0, color: j === 0 ? "6C55C2" : INK } })))];
      s.addTable(rows, { x: 0.6, y: 1.55, w: 12.1, colW: [1.4, 5.9, 4.8], fontSize: 13, fontFace: "Calibri",
        border: { type: "solid", pt: 0.75, color: "D5DCE6" }, valign: "middle", margin: [0.04, 0.1, 0.04, 0.1], rowH: 0.42 });
      H.stats(s, [["21 PASS", "push bản vá: 0 FAIL, khoảng 1 phút 40 giây", GREEN], ["ci-<sha>", "image ứng viên; chỉ gắn tag phát hành khi qua Test + Release"], ["lọc", "chỉ sửa tài liệu → chỉ Gitleaks; dừng ở pha FAIL đầu tiên"]], 5.3);
    } },
    { type: "gates", kicker: "Việc 5 · Git hook và kiểm thử tích hợp", title: "Lỗi bị chặn trước khi rời máy thành viên",
      phases: ["Build", "Release", "Operate"],
      cols: [
        { when: "pre-commit", blocked: true, result: "Commit bị hủy", body: "Cổng tĩnh trên phần đã git add (vài giây). Xóa USER 65532 khỏi Dockerfile.hotfix → LEAST-PRIVILEGE FAIL." },
        { when: "pre-push", blocked: true, result: "Push bị hủy", body: "Đủ 7 pha, triển khai lên 3102. compose chạy root + bỏ cap_drop → runtime.rego báo PRIV-02, PRIV-03." },
        { when: "--no-verify", blocked: true, result: "CI vẫn chặn", body: "Hook né được trên máy; cùng pipeline.sh chạy lại trên GitHub Actions." },
      ],
      note: "Kịch bản tích hợp trong scanSAC.md: 10 tình huống của 4 lỗi, chỉ dùng git commit / git push, đều đã chạy thật ngày 07/11; demo-cleanup.sh đưa repo và stack 3102 về trạng thái sạch." },
    { type: "shotcards", kicker: "Việc 6 · Báo cáo và tài liệu", title: "Báo cáo, sơ đồ và slide dựng từ nguồn trong repo",
      shot: "devsecops-pipeline-cropped.png", caption: "Sơ đồ quy trình DevSecOps sinh bằng script (report/figures/devsecops_pipeline.py)",
      cards: [
        ["Một nguồn, hai bản", "report_concise.md → build_docx.py (Word) và build_pdf.py (PDF); tự đánh số hình, bảng.", "book"],
        ["Bằng chứng chạy thật", "capture_runs.py chạy lệnh thật, ghi log kèm thời điểm và exit code vào report/evidence/.", "camera"],
        ["Kịch bản và slide", "scanSAC.md, F04_THUYET_TRINH.md, slide nhóm và slide từng thành viên.", "file"],
      ] },
    { type: "files", title: "Những gì đã thêm vào kho mã",
      rows: [
        ["Bộ luật Dockerfile + 13 ca kiểm thử", "policy/docker_security*.rego"],
        ["Fixture lỗi và bản vá", "report/fixtures/Dockerfile.*"],
        ["Image đã vá", "deploy/Dockerfile.hotfix"],
        ["Luật runtime + 7 ca kiểm thử", "report/policy/runtime*.rego"],
        ["Pipeline 7 pha, Git hook, cài hook, dọn demo", "devsecops/pipeline.sh, .githooks/"],
        ["Kịch bản tích hợp, demo F04", "report/scanSAC.md, demos/tv4_f04_policy.py"],
        ["Dựng báo cáo, sơ đồ, hình bằng chứng", "report/tools/, report/figures/"],
      ],
      tools: [["Conftest v0.71.1", "Pha 2 · Policy as Code · Build"], ["Dockle 0.4.15", "Pha 6 · CIS image · Release"], ["runtime.rego", "Pha 6 · Compliance as Code"], ["conftest verify", "Pha 7 · kiểm chứng, bàn giao"]] },
    { type: "end", headline: "Chính sách thành mã, kiểm ở ba thời điểm — và một pipeline nối mọi cổng của nhóm",
      done: ["Bộ luật Dockerfile + runtime: 26/26 ca; hotfix đạt sạch", "pipeline.sh + Git hook: push bản vá 21 PASS · 0 FAIL", "Báo cáo DOCX/PDF, kịch bản tích hợp, slide"],
      limits: ["Đã tự tìm 10 cách lách bộ luật, vd USER ${ARG} mặc định 0", "Luật bí mật dò theo tên: DB_PASS lọt, *_FILE bị chặn nhầm", "Nhãn OCI là tự khai — chưa đạt SLSA"],
      next: ["Vá 10 điểm lách, mỗi điểm thêm một ca kiểm thử", "CODEOWNERS cho policy/, devsecops/, .trivyignore", "Ký image (cosign), SBOM + provenance SLSA"] },
  ],
};

(async () => {
  for (const d of [THANG, THUY, QUOCANH, VU]) console.log("wrote", await buildDeck(d, process.env.OUT_DIR));
})().catch((e) => { console.error(e); process.exit(1); });
