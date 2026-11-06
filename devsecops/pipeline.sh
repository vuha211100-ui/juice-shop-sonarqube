#!/usr/bin/env bash
# =============================================================================
# DevSecOps pipeline — OWASP Juice Shop (SEC4349)
# Chạy các cổng kiểm soát theo sơ đồ DevSecOps của báo cáo:
#   Code → Build → Test → Release → Deploy → Operate → Monitor
# Gọi tự động từ Git hook (.githooks/pre-commit, .githooks/pre-push) và GitHub Actions
# (.github/workflows/devsecops.yml), hoặc chạy tay:
#   bash devsecops/pipeline.sh [tùy chọn] [pha ...]
#
# Pha:  code build test release deploy operate monitor | all (mặc định)
# Tùy chọn:
#   --staged     thay đổi = vùng staging (pre-commit)
#   --base REV   thay đổi = REV..HEAD (pre-push, CI). Mặc định: v20.2.0 so với cây làm việc
#   --quick      chỉ các cổng tĩnh (không tsc, không build image, không deploy)
#   --no-apply   pha Deploy chỉ kiểm chính sách, không chạy docker compose up
#   --full       bỏ lọc theo loại thay đổi, chạy mọi cổng của các pha đã chọn
#   --mark       khi đạt, ghi dấu .devsecops/pass-<sha> (pre-push bỏ qua lần đẩy lặp lại)
# Mã thoát: 0 = không có cổng FAIL (WARN không chặn), 1 = có cổng FAIL.
# =============================================================================
set -uo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'   # Git Bash: không đổi /work, /scan... thành đường dẫn Windows

cd "$(git rev-parse --show-toplevel)" || exit 1
ROOT=$(pwd -W 2>/dev/null || pwd)
OUT=.devsecops
mkdir -p "$OUT"

# Phiên bản công cụ — khớp bảng "Phương pháp thực nghiệm" của báo cáo
SEMGREP_IMG=semgrep/semgrep:1.180.0
GITLEAKS_IMG=zricethezav/gitleaks:v8.30.1
CONFTEST_IMG=openpolicyagent/conftest:v0.71.1
TRIVY_IMG=aquasec/trivy:0.76.1
DOCKLE_IMG=goodwithtech/dockle:v0.4.15
IMAGE=juice-shop:hotfix-f01-f02                      # tag docker-compose.yml triển khai — chỉ gắn khi qua pha Release
CANDIDATE=juice-shop:ci-$(git rev-parse --short HEAD)  # image ứng viên do pha Build tạo ra
APP_URL=http://127.0.0.1:3102
PROM_URL=http://127.0.0.1:9090
UPSTREAM_BASE=5658473cf8814459bf89000ce373b20ed0b4eb37   # tag v20.2.0 (Juice Shop gốc, trước commit đầu của nhóm)

# Phạm vi thay đổi
SEMGREP_SCOPE='^((routes|lib|models|data)/.*\.(ts|js)|(server|app)\.ts)$'
APP_SCOPE='^(routes/|lib/|models/|data/|config/|views/|server\.ts|app\.ts|package(-lock)?\.json|tsconfig\.json|test/api/)'
INFRA_SCOPE='^(Dockerfile|deploy/|docker-compose\.yml|policy/|report/policy/|devsecops/)'
HOTFIX_FILES='^routes/(login|fileServer)\.ts$'   # deploy/Dockerfile.hotfix chỉ chép 2 route này vào image

MODE=worktree BASE="" QUICK=0 NO_APPLY=0 FULL=0 MARK=0 STAGES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --staged) MODE=staged ;;
    --base) MODE=commit; BASE=$2; shift ;;
    --quick) QUICK=1 ;;
    --no-apply) NO_APPLY=1 ;;
    --full) FULL=1 ;;
    --mark) MARK=1 ;;
    all) STAGES+=(code build test release deploy operate monitor) ;;
    code|build|test|release|deploy|operate|monitor) STAGES+=("$1") ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "Tham số không hợp lệ: $1" >&2; exit 2 ;;
  esac
  shift
done
[ ${#STAGES[@]} -eq 0 ] && STAGES=(code build test release deploy operate monitor)
[ "$MODE" = worktree ] && BASE=$UPSTREAM_BASE
[ "$MODE" = staged ] && BASE=HEAD
if ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
  echo "Không tìm thấy commit gốc '$BASE' — dùng $UPSTREAM_BASE (v20.2.0)"; BASE=$UPSTREAM_BASE
fi

# Danh sách tệp thay đổi
case $MODE in
  staged) CHANGED=$(git diff --cached --name-only --diff-filter=ACMR) ;;
  commit) CHANGED=$(git diff --name-only --diff-filter=ACMR "$BASE" HEAD) ;;
  worktree) CHANGED=$( (git diff --name-only --diff-filter=ACMR "$BASE"; git ls-files --others --exclude-standard) | sort -u) ;;
esac
pick() { printf '%s\n' "$CHANGED" | grep -E "$1" || true; }
APP_CHANGED=$(pick "$APP_SCOPE"); INFRA_CHANGED=$(pick "$INFRA_SCOPE")
has_app() { [ "$FULL" = 1 ] || [ -n "$APP_CHANGED" ]; }
has_infra() { [ "$FULL" = 1 ] || [ -n "$INFRA_CHANGED" ]; }
nlines() { [ -z "$1" ] && echo 0 || printf '%s\n' "$1" | wc -l | tr -d ' '; }

# ---------- khung chạy cổng ----------
RESULTS=() FAILED=0 SEQ=0
for s in "${STAGES[@]}"; do rm -f "$OUT"/[0-9][0-9]-"${s^}".log; done   # chỉ xóa log của các pha chạy lần này (CI gọi từng pha một)
record() { RESULTS+=("$1|$2|$3|$4"); }
line() {   # căn cột theo số ký tự (printf %-Ns đếm byte, lệch với tiếng Việt có dấu)
  local pad=$((48 - ${#2})); [ $pad -lt 1 ] && pad=1
  printf '  %-8s %s%*s%s\n' "$1" "$2" "$pad" '' "$3"
}
newlog() { SEQ=$((SEQ + 1)); LOG=$(printf '%s/%02d-%s.log' "$OUT" "$SEQ" "$1"); }   # đặt biến LOG (không dùng $(...) để SEQ tăng thật)
# gate <pha> <tên> <lệnh...>  : lệnh lỗi -> FAIL (chặn)
gate() {
  local phase=$1 name=$2; shift 2
  newlog "$phase"; local log=$LOG
  if "$@" >"$log" 2>&1; then line "$phase" "$name" "PASS"; record PASS "$phase" "$name" "$log"
  else line "$phase" "$name" "FAIL  → $log"; record FAIL "$phase" "$name" "$log"; FAILED=1
    tail -n 20 "$log" | sed 's/^/           │ /'; fi
}
# warn <pha> <tên> <lệnh...>  : lệnh lỗi -> WARN (không chặn)
warn() {
  local phase=$1 name=$2; shift 2
  newlog "$phase"; local log=$LOG
  if "$@" >"$log" 2>&1; then line "$phase" "$name" "PASS"; record PASS "$phase" "$name" "$log"
  else line "$phase" "$name" "WARN  → $log"; record WARN "$phase" "$name" "$log"
    tail -n 12 "$log" | sed 's/^/           │ /'; fi
}
skip() { line "$1" "$2" "SKIP  ($3)"; record SKIP "$1" "$2" "$3"; }

conftest() { docker run --rm -v "$ROOT:/work:ro" -w /work "$CONFTEST_IMG" "$@" --no-color; }
image_exists() { docker image inspect "$CANDIDATE" >/dev/null 2>&1 || { echo "Chưa có image ứng viên $CANDIDATE — chạy pha build trước"; return 1; }; }

# ---------- Code: SAST (Semgrep, chỉ cảnh báo mới) + quét secret (Gitleaks) ----------
semgrep_new_findings() {
  local files=$1 sg="$OUT/sg"
  rm -rf "$sg"; mkdir -p "$sg/head" "$sg/base"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    mkdir -p "$sg/head/$(dirname "$f")" "$sg/base/$(dirname "$f")"
    case $MODE in
      staged) git show ":$f" >"$sg/head/$f" ;;
      commit) git show "HEAD:$f" >"$sg/head/$f" ;;
      worktree) cp "$f" "$sg/head/$f" ;;
    esac
    if git cat-file -e "$BASE:$f" 2>/dev/null; then git show "$BASE:$f" >"$sg/base/$f"; fi
  done <<<"$files"
  echo "Tệp quét (bản mới so với $BASE):"; printf '  %s\n' $files
  docker run --rm -e SEMGREP_SEND_METRICS=off -v "$ROOT/$sg:/scan" -v "$ROOT/report/semgrep-rules:/rules:ro" "$SEMGREP_IMG" \
    semgrep scan --metrics=off --quiet --json --config /rules/owasp-top-ten.yml --config /rules/nodejsscan.yml /scan >"$OUT/semgrep.json" || return 1
  node devsecops/semgrep-diff.mjs "$sg" "$OUT/semgrep.json"
}
gl() { docker run --rm -i -v "$ROOT:/repo:ro" "$GITLEAKS_IMG" "$@" --no-banner --no-color --redact -v; }
added_lines() { grep '^+' | grep -v '^+++' || true; }   # chỉ dòng được THÊM: secret có sẵn của Juice Shop gốc không chặn
gitleaks_scan() {
  local out rc
  if [ "$MODE" = staged ]; then
    out=$(git diff --cached -U0 --no-color | added_lines | gl stdin --config /repo/.gitleaks.toml 2>&1); rc=$?
  elif [ -d .git ]; then           # clone thường (máy thành viên, CI): quét từng commit BASE..HEAD
    out=$(gl git --log-opts="$BASE..HEAD" /repo 2>&1); rc=$?
  else                             # git worktree: container không đọc được .git dạng tệp -> đưa diff qua stdin
    out=$(git log -p -U0 --no-color "$BASE..HEAD" | added_lines | gl stdin --config /repo/.gitleaks.toml 2>&1); rc=$?
  fi
  if [ "$MODE" = worktree ] && [ $rc = 0 ]; then   # thêm phần chưa commit trên cây làm việc
    out+=$'\n'$(git diff HEAD -U0 --no-color | added_lines | gl stdin --config /repo/.gitleaks.toml 2>&1); rc=$?
  fi
  echo "$out"
  if echo "$out" | grep -q 'ERR'; then echo "Gitleaks báo lỗi khi quét — không coi là đạt"; return 1; fi
  return $rc
}
st_code() {
  gate Code "Gitleaks — quét secret" gitleaks_scan
  local sfiles; sfiles=$(pick "$SEMGREP_SCOPE")
  if [ -n "$sfiles" ]; then gate Code "Semgrep — SAST, chặn cảnh báo mới" semgrep_new_findings "$sfiles"
  else skip Code "Semgrep — SAST, chặn cảnh báo mới" "không đổi mã server"; fi
}

# ---------- Build: Policy as Code (Dockerfile) + biên dịch + đóng gói image ----------
hotfix_coverage() {
  local out; out=$(pick '^(routes/|lib/|models/|data/|server\.ts|app\.ts)' | grep -vE "$HOTFIX_FILES" || true)
  [ -z "$out" ] && { echo "Mọi thay đổi mã server đều nằm trong 2 route được đóng gói."; return 0; }
  echo "deploy/Dockerfile.hotfix chỉ chép routes/login.js và routes/fileServer.js vào image."
  echo "Các thay đổi sau KHÔNG có trong image triển khai (cần sửa Dockerfile.hotfix nếu muốn đưa lên):"
  printf '  %s\n' $out; return 1
}
build_image() {
  docker build -f deploy/Dockerfile.hotfix --build-arg VCS_REF="$(git rev-parse --short HEAD)" -t "$CANDIDATE" build
}
tsc_build() { [ -d node_modules ] || { echo "Thiếu node_modules — chạy npm install"; return 1; }; npm run --silent build:server; }
st_build() {
  if ! has_app && ! has_infra; then skip Build "Build" "không đổi mã/hạ tầng"; return; fi
  gate Build "Conftest verify — unit test luật Rego" conftest verify -p policy -p report/policy
  gate Build "Conftest — Dockerfile (docker_security.rego)" conftest test Dockerfile deploy/Dockerfile.hotfix --parser dockerfile -p policy --namespace dockerfile
  if [ "$QUICK" = 1 ]; then skip Build "tsc + docker build" "--quick"; return; fi
  warn Build "Phạm vi image hotfix" hotfix_coverage
  gate Build "tsc — biên dịch server" tsc_build
  [ "$FAILED" = 0 ] && gate Build "docker build — $CANDIDATE" build_image
}

# ---------- Test: kiểm thử bảo mật (TDS) ----------
st_test() {
  if ! has_app; then skip Test "node:test — test/api/security" "không đổi mã ứng dụng"; return; fi
  [ "$QUICK" = 1 ] && { skip Test "node:test — test/api/security" "--quick"; return; }
  gate Test "node:test — test/api/security" security_tests
}
security_tests() {
  # Juice Shop tự kiểm điều kiện khởi động: cần server đã biên dịch và frontend đã build (npm install chạy postinstall)
  local f; for f in build/server.js frontend/dist/frontend/index.html; do
    [ -f "$f" ] || { echo "Thiếu $f — chạy 'npm install' (postinstall build frontend) rồi 'npm run build:server'"; return 1; }
  done
  node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit "test/api/security/**/*.test.ts"
}

# ---------- Release: quét image đã build ----------
trivy_scan() {
  image_exists || return 1
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v devsecops-trivy-cache:/root/.cache \
    -v "$ROOT/devsecops:/cfg:ro" "$TRIVY_IMG" image --scanners vuln --severity CRITICAL \
    --ignorefile /cfg/.trivyignore --exit-code 1 --no-progress "$CANDIDATE"
}
dockle_scan() {
  image_exists || return 1
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$DOCKLE_IMG" --exit-code 1 --exit-level warn "$CANDIDATE"
}
promote() { docker tag "$CANDIDATE" "$IMAGE" && docker image inspect "$IMAGE" --format "$IMAGE = {{.Id}}"; }
st_release() {
  if ! has_app && ! has_infra; then skip Release "Trivy + Dockle" "không đổi mã/hạ tầng"; return; fi
  [ "$QUICK" = 1 ] && { skip Release "Trivy + Dockle" "--quick"; return; }
  gate Release "Trivy — CVE CRITICAL mới (SCA)" trivy_scan
  gate Release "Dockle — CIS image (WARN/FATAL)" dockle_scan
  [ "$FAILED" = 0 ] && gate Release "Gắn tag phát hành $IMAGE" promote
}

# ---------- Deploy: Policy as Code (compose) + triển khai ----------
deploy_apply() {
  docker volume create juice-report-accesslogs >/dev/null
  docker compose up -d --no-build --wait --wait-timeout 240 && docker compose ps
}
st_deploy() {
  if ! has_app && ! has_infra; then skip Deploy "Deploy" "không đổi mã/hạ tầng"; return; fi
  gate Deploy "Conftest — docker-compose.yml (compose.rego)" conftest test docker-compose.yml -p policy --namespace compose
  gate Deploy "docker compose config" docker compose config -q
  if [ "$QUICK" = 1 ] || [ "$NO_APPLY" = 1 ]; then skip Deploy "docker compose up (3102)" "chỉ kiểm chính sách"; return; fi
  [ "$FAILED" = 0 ] && gate Deploy "docker compose up (3102)" deploy_apply
}

# ---------- Operate: Compliance as Code trên container đang chạy ----------
runtime_compliance() {
  local files=() c
  for c in juice-app-juice-shop-1 juice-app-proxy-1; do
    docker inspect --format '{{json .}}' "$c" >"$OUT/inspect-$c.json" || { echo "Container $c không chạy"; return 1; }
    files+=("$OUT/inspect-$c.json")
  done
  conftest test "${files[@]}" -p report/policy --namespace runtime
}
http_code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
check_app() { local c; c=$(http_code "$APP_URL/"); echo "GET / → $c"; [ "$c" = 200 ]; }
check_metrics() { local c; c=$(http_code "$APP_URL/metrics"); echo "GET /metrics → $c (yêu cầu 404)"; [ "$c" = 404 ]; }
check_headers() {
  local h; h=$(curl -s -D - -o /dev/null "$APP_URL/" | tr -d '\r'); echo "$h"
  echo "$h" | grep -qi '^x-content-type-options: nosniff' && echo "$h" | grep -qi '^referrer-policy: no-referrer'
}
check_ratelimit() {
  local i c
  for i in $(seq 1 12); do
    c=$(http_code -X POST "$APP_URL/rest/user/login"); echo "POST /rest/user/login #$i → $c"
    [ "$c" = 429 ] && return 0
  done
  return 1
}
st_operate() {
  gate Operate "Conftest — runtime.rego (docker inspect)" runtime_compliance
  gate Operate "Proxy phục vụ ứng dụng (/ → 200)" check_app
  gate Operate "F03 — /metrics bị chặn (404)" check_metrics
  gate Operate "Header nosniff + no-referrer" check_headers
  gate Operate "Rate-limit đăng nhập (→ 429)" check_ratelimit
}

# ---------- Monitor: Prometheus + luật cảnh báo ----------
prom_target_up() {
  local i s
  for i in $(seq 1 12); do
    s=$(curl -s "$PROM_URL/api/v1/targets" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const t=JSON.parse(d).data.activeTargets.find(x=>x.labels.job==="juice-shop");console.log(t?t.health:"missing")})')
    echo "target juice-shop: $s"; [ "$s" = up ] && return 0; sleep 5
  done
  return 1
}
prom_rule_loaded() {
  local r; r=$(curl -s "$PROM_URL/api/v1/rules"); echo "$r" | grep -o '"name":"HighClientErrorRate"[^}]*"state":"[a-z]*"' || true
  echo "$r" | grep -q '"name":"HighClientErrorRate"'
}
st_monitor() {
  if ! curl -sf "$PROM_URL/-/ready" >/dev/null 2>&1; then
    skip Monitor "Prometheus + cảnh báo" "chưa chạy: docker compose -f docker-compose.monitoring.yml up -d"; return
  fi
  gate Monitor "Prometheus scrape /metrics nội bộ (UP)" prom_target_up
  gate Monitor "Luật cảnh báo HighClientErrorRate" prom_rule_loaded
}

# ---------- chạy ----------
echo "══ DevSecOps pipeline · $(git rev-parse --abbrev-ref HEAD)@$(git rev-parse --short HEAD) ══"
echo "  Nguồn thay đổi: $MODE · gốc so sánh: $(git rev-parse --short "$BASE")"
echo "  Tệp thay đổi: $(nlines "$CHANGED") (mã ứng dụng: $(nlines "$APP_CHANGED"), hạ tầng: $(nlines "$INFRA_CHANGED"))$([ "$FULL" = 1 ] && echo ' · --full')"
[ "$MODE" = commit ] && [ -n "$(git status --porcelain --untracked-files=no)" ] && echo "  Lưu ý: cây làm việc có thay đổi chưa commit — build/test dùng bản trên đĩa"
for s in code build test release deploy operate monitor; do
  printf '%s\n' "${STAGES[@]}" | grep -qx "$s" || continue
  # --quick (pre-commit): chạy hết các cổng tĩnh để thấy mọi lỗi một lần; còn lại dừng ở pha FAIL đầu tiên
  if [ "$FAILED" = 1 ] && [ "$QUICK" = 0 ]; then skip "${s^}" "(cả pha)" "pha trước FAIL"; continue; fi
  "st_$s"
done

# ---------- tổng kết ----------
pass=0 warns=0 fails=0 skips=0
{
  echo "| Kết quả | Pha | Cổng |"; echo "|---|---|---|"
  for r in "${RESULTS[@]}"; do IFS='|' read -r st ph nm _ <<<"$r"; echo "| $st | $ph | $nm |"; done
} >"$OUT/summary.md"
for r in "${RESULTS[@]}"; do case ${r%%|*} in PASS) pass=$((pass+1));; WARN) warns=$((warns+1));; FAIL) fails=$((fails+1));; SKIP) skips=$((skips+1));; esac; done
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$OUT/summary.md" >>"$GITHUB_STEP_SUMMARY"
echo "══ Tổng: $pass PASS · $warns WARN · $fails FAIL · $skips SKIP — log: $OUT/ ══"
if [ "$FAILED" = 1 ]; then echo "✗ Pipeline FAIL — sửa lỗi ở cổng FAIL rồi chạy lại."; exit 1; fi
[ "$MARK" = 1 ] && : >"$OUT/pass-$(git rev-parse HEAD)"
echo "✓ Pipeline đạt."
