#!/usr/bin/env bash
# Bật Git hook DevSecOps cho bản clone này (mỗi thành viên chạy một lần sau khi clone).
# Git không tự chép hook theo repo, nên hook nằm trong .githooks/ và trỏ core.hooksPath vào đó.
set -e
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
chmod +x .githooks/* devsecops/*.sh 2>/dev/null || true
docker volume create devsecops-trivy-cache >/dev/null 2>&1 || true
echo "Đã bật hook: $(git config core.hooksPath)/{pre-commit,pre-push}"
echo "Kiểm tra công cụ:"
for t in git docker node npm curl; do printf '  %-7s %s\n' "$t" "$(command -v "$t" >/dev/null && echo OK || echo THIẾU)"; done
docker info >/dev/null 2>&1 && echo "  Docker daemon OK" || echo "  Docker daemon CHƯA CHẠY — hook cần Docker"
[ -d node_modules ] && echo "  node_modules OK" || echo "  Thiếu node_modules — chạy: npm install"
