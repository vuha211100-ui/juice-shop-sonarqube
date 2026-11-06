#!/usr/bin/env bash
# Dọn sau buổi demo tích hợp DevSecOps (devsecops/DEMO.md) — đưa repo về trạng thái sạch:
#   1. trả lại các tệp demo đã sửa (routes/login.ts, docker-compose.yml, deploy/Dockerfile.hotfix)
#   2. về nhánh main, xóa nhánh demo fix/demo-ci (local + GitHub) và các lần chạy Actions của nó
#   3. gỡ tag image ứng viên juice-shop:ci-*, xóa log .devsecops/
#   4. kiểm tra lại: tệp sạch, main == remote, image triển khai còn, stack 3102 đang chạy
# Dùng (Git Bash, tại gốc repo):  bash devsecops/demo-cleanup.sh        (hỏi xác nhận trước khi trả tệp)
#                                 bash devsecops/demo-cleanup.sh -y     (không hỏi)
# Chỉ đụng tới những thứ demo tạo ra; các thay đổi chưa commit khác (vd report/) được giữ nguyên.
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(git rev-parse --show-toplevel)" || exit 1

REMOTE=${REMOTE:-github}
DEMO_BRANCH=fix/demo-ci
DEMO_FILES=(routes/login.ts docker-compose.yml deploy/Dockerfile.hotfix)
IMAGE=juice-shop:hotfix-f01-f02
YES=0; [ "${1:-}" = "-y" ] && YES=1
ok() { echo "  ✓ $*"; }
info() { echo "  · $*"; }
bad() { echo "  ✗ $*"; PROBLEM=1; }
PROBLEM=0

echo "══ 1. Trả lại các tệp demo đã sửa ══"
dirty=$(git status --porcelain -- "${DEMO_FILES[@]}")
if [ -z "$dirty" ]; then ok "các tệp demo đã sạch"
else
  echo "$dirty" | sed 's/^/    /'
  git --no-pager diff --stat HEAD -- "${DEMO_FILES[@]}" | sed 's/^/    /'
  ans=y
  if [ "$YES" = 0 ]; then read -r -p "  Trả các tệp trên về bản đã commit (mất thay đổi chưa commit của chúng)? [y/N] " ans; fi
  if [ "$ans" = y ] || [ "$ans" = Y ]; then
    git restore --staged --worktree -- "${DEMO_FILES[@]}" && ok "đã trả lại ${DEMO_FILES[*]}"
  else bad "giữ nguyên theo lựa chọn — chạy lại khi muốn dọn"; fi
fi

echo "══ 2. Nhánh demo $DEMO_BRANCH ══"
cur=$(git rev-parse --abbrev-ref HEAD)
if [ "$cur" = "$DEMO_BRANCH" ]; then
  if git switch -q main; then ok "đã chuyển về main"; else bad "không chuyển được về main (còn tệp chưa sạch?)"; fi
elif [ "$cur" != main ]; then info "đang ở nhánh '$cur' (không phải nhánh demo) — để nguyên"
fi
if git show-ref -q --verify "refs/heads/$DEMO_BRANCH"; then
  git branch -q -D "$DEMO_BRANCH" && ok "đã xóa nhánh local $DEMO_BRANCH"
else ok "không có nhánh local $DEMO_BRANCH"; fi
if git ls-remote --exit-code --heads "$REMOTE" "$DEMO_BRANCH" >/dev/null 2>&1; then
  git push -q --no-verify "$REMOTE" --delete "$DEMO_BRANCH" && ok "đã xóa nhánh $DEMO_BRANCH trên $REMOTE"
else ok "không có nhánh $DEMO_BRANCH trên $REMOTE"; fi
git fetch -q --prune "$REMOTE" 2>/dev/null || true

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  repo=$(git remote get-url "$REMOTE" | sed -E 's#(\.git)?$##; s#.*github\.com[:/]##')
  runs=$(gh run list -R "$repo" --branch "$DEMO_BRANCH" --limit 50 --json databaseId,status -q '.[] | "\(.databaseId) \(.status)"' 2>/dev/null || true)
  if [ -z "$runs" ]; then ok "không có lần chạy Actions nào của $DEMO_BRANCH"
  else
    while read -r id st; do
      [ -z "$id" ] && continue
      [ "$st" != completed ] && gh run cancel "$id" -R "$repo" >/dev/null 2>&1 && sleep 3
      gh run delete "$id" -R "$repo" >/dev/null 2>&1 && ok "đã xóa lần chạy Actions $id" || info "chưa xóa được lần chạy $id (đang dừng) — chạy lại script sau ít giây"
    done <<<"$runs"
  fi
else info "không có gh (hoặc chưa đăng nhập) — bỏ qua dọn lần chạy Actions của nhánh demo"; fi

echo "══ 3. Image ứng viên + log ══"
tags=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep '^juice-shop:ci-' || true)
if [ -n "$tags" ]; then
  deployed=$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || true)
  for t in $tags; do
    if docker rmi "$t" >/dev/null 2>&1; then ok "gỡ tag $t"
    elif [ -n "$deployed" ] && [ "$(docker image inspect -f '{{.Id}}' "$t")" = "$deployed" ]; then
      # tag phụ của chính image đang triển khai: -f chỉ bỏ tên, image + container giữ nguyên
      docker rmi -f "$t" >/dev/null 2>&1 && ok "gỡ tag $t (cùng image với $IMAGE)"
    else info "giữ $t — image đang được container dùng"; fi
  done
else ok "không còn image ứng viên juice-shop:ci-*"; fi
rm -rf .devsecops && ok "đã xóa .devsecops/ (log, dấu pass của pre-push)"

echo "══ 4. Kiểm tra lại ══"
[ -z "$(git status --porcelain -- "${DEMO_FILES[@]}")" ] && ok "tệp demo sạch" || bad "tệp demo vẫn còn thay đổi"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] && ok "đang ở main" || info "đang ở $(git rev-parse --abbrev-ref HEAD)"
if git rev-parse -q --verify "refs/remotes/$REMOTE/main" >/dev/null; then
  [ "$(git rev-parse main)" = "$(git rev-parse "$REMOTE/main")" ] && ok "main khớp $REMOTE/main ($(git rev-parse --short main))" \
    || info "main ($(git rev-parse --short main)) khác $REMOTE/main ($(git rev-parse --short "$REMOTE/main"))"
fi
[ "$(git config core.hooksPath)" = .githooks ] && ok "Git hook vẫn bật (core.hooksPath=.githooks)" || info "Git hook chưa bật: bash devsecops/install-hooks.sh"
docker image inspect "$IMAGE" >/dev/null 2>&1 && ok "image triển khai $IMAGE còn" || bad "thiếu $IMAGE — chạy: bash devsecops/pipeline.sh"
if docker inspect -f '{{.State.Running}}' juice-app-juice-shop-1 2>/dev/null | grep -q true \
   && docker inspect -f '{{.State.Running}}' juice-app-proxy-1 2>/dev/null | grep -q true; then
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3102/ || true)
  [ "$code" = 200 ] && ok "stack 3102 chạy (GET / → 200)" || info "stack chạy nhưng GET / → $code"
else info "stack 3102 không chạy — bật lại: docker compose up -d"; fi
others=$(git status --porcelain | grep -v -- '\.devsecops' || true)
[ -n "$others" ] && info "các thay đổi chưa commit khác được GIỮ NGUYÊN: $(printf '%s\n' "$others" | wc -l | tr -d ' ') tệp (git status)"

echo
[ "$PROBLEM" = 0 ] && echo "✓ Đã dọn xong." || { echo "✗ Còn mục cần xử lý (xem ✗ ở trên)."; exit 1; }
