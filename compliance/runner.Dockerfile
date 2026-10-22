# Công cụ chạy Phase 6 trên Windows: Cinc Auditor (bản build mã nguồn mở của Chef InSpec)
# + Docker CLI, để control dùng `docker inspect` qua socket Docker của máy chủ.
#   docker build -t sac-auditor -f compliance/runner.Dockerfile compliance
FROM docker:29-cli AS cli

FROM cincproject/auditor:latest
COPY --from=cli /usr/local/bin/docker /usr/local/bin/docker
# Chạy với user mặc định của image: /var/run/docker.sock chỉ root đọc được.
# Container công cụ này được gắn docker.sock nên tương đương quyền root trên Docker host;
# chỉ dùng cục bộ, không dùng cho dịch vụ chạy lâu dài.
