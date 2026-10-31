# Policy as Code cho Dockerfile của Juice Shop — theo mô hình "Policy as Code with Conftest".
# Mỗi luật đặt tại điểm thực thi đúng thay vì các "original check" dễ bị qua mặt:
#   Least privilege  -> USER ở STAGE CUỐI, UID số, không phải root (thay vì "có USER bất kỳ trong file")
#   Firewall/RBAC    -> cổng quản trị/DB không được EXPOSE (giảm bề mặt tấn công)
#   Supply chain     -> metadata nguồn gốc (nhãn OCI source+revision; hỗ trợ truy vết, CHƯA đánh giá đạt SLSA) + không :latest, không ADD, cảnh báo base chưa ghim digest
#   Secret hygiene   -> KHÔNG nhúng bí mật (ENV/ARG) vào image (cải tiến của nhóm, ngoài bản mẫu lab)
# Mỗi thông báo vi phạm trích sẵn điều khoản chuẩn quốc tế áp dụng (CIS Docker, PCI-DSS, NIST, OCI/SLSA).
#   chạy: conftest test <Dockerfile> -p policy/ --namespace dockerfile
package dockerfile

import rego.v1

# Danh sách cổng quản trị/CSDL — giữ theo Appendix A.1 của lab (SSH, telnet, Docker daemon, MySQL, Postgres, Redis, Mongo).
forbidden_ports := {"22", "23", "2375", "2376", "3306", "5432", "6379", "27017"}

required_labels := {"org.opencontainers.image.source", "org.opencontainers.image.revision"}

# UID là phần trước dấu ':' trong 'USER uid[:gid]'. Nhận diện root ('0' hoặc 'root') độc lập với group
# kèm theo, nên 'USER 0:1000' cũng bị nhận diện là root.
uid_of(u) := split(u, ":")[0]

# Chỉ STAGE CUỐI tạo ra image chạy thật; USER ở stage builder không áp dụng cho runtime.
final_stage := max([ins.Stage | some ins in input])

final_users := [ins.Value[0] | some ins in input; ins.Stage == final_stage; ins.Cmd == "user"]

last_user := final_users[count(final_users) - 1] if count(final_users) > 0

# LEAST-PRIVILEGE ------------------------------------------------------------
deny contains msg if {
	count(final_users) == 0
	msg := "LEAST-PRIVILEGE: final stage has no explicit USER; policy requires an explicit non-root USER (otherwise the container may run as root). (CIS Docker 4.1; PCI-DSS 2.2; NIST SP 800-190)"
}

deny contains msg if {
	uid_of(last_user) in {"root", "0"}
	msg := sprintf("LEAST-PRIVILEGE: final USER '%s' runs as root (UID 0), regardless of group. (CIS Docker 4.1; PCI-DSS 2.2)", [last_user])
}

warn contains msg if {
	last_user
	not uid_of(last_user) in {"root", "0"}
	not regex.match(`^[0-9]+(:[0-9]+)?$`, last_user)
	msg := sprintf("LEAST-PRIVILEGE: final USER '%s' is not a fixed numeric UID. (CIS Docker 4.1)", [last_user])
}

# ATTACK-SURFACE (firewall / RBAC) ------------------------------------------
port_number(raw) := split(raw, "/")[0] # bỏ hậu tố /tcp, /udp

deny contains msg if {
	some ins in input
	ins.Cmd == "expose"
	some raw in ins.Value
	port_number(raw) in forbidden_ports
	msg := sprintf("ATTACK-SURFACE: EXPOSE '%s' covers administrative/database port %s. (CIS Docker 5.8; NIST SP 800-190)", [raw, port_number(raw)])
}

# SUPPLY-CHAIN — provenance khai báo (traceability; không thay cho chữ ký/attestation) --
label_blob := concat(" ", [concat(" ", ins.Value) | some ins in input; ins.Cmd == "label"])

deny contains msg if {
	some req in required_labels
	not contains(label_blob, req)
	msg := sprintf("SUPPLY-CHAIN: missing provenance label '%s' (metadata nguồn gốc hỗ trợ truy vết; chưa đánh giá đạt mức SLSA). (OCI image-spec; NIST SSDF)", [req])
}

# SUPPLY-CHAIN — base image (không :latest/ADD, ghim digest) -----------------
deny contains msg if {
	some ins in input
	ins.Cmd == "from"
	endswith(ins.Value[0], ":latest")
	msg := sprintf("SUPPLY-CHAIN: base image '%s' uses :latest; pin a version or digest. (CIS Docker Benchmark §4 Container Images; NIST SSDF)", [ins.Value[0]])
}

deny contains msg if {
	some ins in input
	ins.Cmd == "add"
	msg := "SUPPLY-CHAIN: use COPY instead of ADD to avoid remote/implicit extraction. (CIS Docker 4.9)"
}

warn contains msg if {
	some ins in input
	ins.Cmd == "from"
	not contains(ins.Value[0], "@sha256:")
	not endswith(ins.Value[0], ":latest")
	msg := sprintf("SUPPLY-CHAIN: base image '%s' is not pinned by digest (digest pin khác với Content Trust/CIS 4.5). (CIS Docker Benchmark §4; NIST SSDF)", [ins.Value[0]])
}

# SECRET-IN-IMAGE — cải tiến của nhóm (ngoài bản mẫu lab) --------------------
# Bí mật đặt trong ENV/ARG bị bake vào layer ảnh và lộ qua `docker history`. Ánh xạ
# luật secret của compose (F03) xuống tầng Dockerfile. ENV parse thành [key, value, "=", ...];
# ARG parse thành ["KEY=VALUE"].
secret_key := `(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)`

deny contains msg if {
	some ins in input
	ins.Cmd == "env"
	some i, key in ins.Value
	i % 3 == 0
	i + 1 < count(ins.Value)
	regex.match(secret_key, key)
	ins.Value[i + 1] != ""
	msg := sprintf("SECRET-IN-IMAGE: ENV '%s' hardcodes a credential into the image (exposed via docker history); use build secrets/runtime env. (CIS Docker 4.10; GDPR Art.32; PCI-DSS 8.2.1)", [key])
}

deny contains msg if {
	some ins in input
	ins.Cmd == "arg"
	some tok in ins.Value
	contains(tok, "=")
	regex.match(secret_key, split(tok, "=")[0])
	split(tok, "=")[1] != ""
	msg := sprintf("SECRET-IN-IMAGE: ARG '%s' bakes a credential default into the image. (CIS Docker 4.10; GDPR Art.32; PCI-DSS 8.2.1)", [split(tok, "=")[0]])
}
