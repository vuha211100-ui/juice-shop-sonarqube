package compose

import rego.v1

# Input: file docker-compose (conftest tự đọc YAML).
# ports chấp nhận cả 3 dạng của Compose: "127.0.0.1:3102:8080", 3000, {target, published, host_ip}.
# Thông báo vi phạm trích điều khoản chuẩn quốc tế (GDPR, PCI-DSS, CIS Docker) và Việt Nam
# (Nghị định 13/2023/NĐ-CP Điều 26; Luật An toàn thông tin mạng 2015 Điều 19).

host_ip(p) := split(p, ":")[0] if {
	is_string(p)
	count(split(p, ":")) == 3
}

host_ip(p) := "" if {
	is_string(p)
	count(split(p, ":")) < 3
}

host_ip(p) := "" if is_number(p)

host_ip(p) := object.get(p, "host_ip", "") if is_object(p)

ports(svc) := object.get(svc, "ports", [])

# Dịch vụ được thiết kế để nhận kết nối từ host (reverse proxy, dashboard) phải tự khai báo nhãn.
edge(svc) if object.get(object.get(svc, "labels", {}), "lab.exposure", "") == "edge"

# F03 / NET-02: backend không được publish cổng. Nếu backend có cổng host, mọi route (kể cả /metrics)
# có thể bị truy cập vòng qua proxy, làm vô hiệu luật chặn /metrics và giới hạn tốc độ ở proxy.
deny contains msg if {
	some name, svc in input.services
	count(ports(svc)) > 0
	not edge(svc)
	msg := sprintf("[F03 NET-02] service '%s' publishes ports but is not an edge service (label lab.exposure=edge); backend must only be reachable through the proxy (Luật ATTTM 2015 Đ.19; NĐ 13/2023 Đ.26)", [name])
}

# NET-01 (GDPR Art.32): cổng publish chỉ được bind loopback trong lab.
deny contains msg if {
	some name, svc in input.services
	some p in ports(svc)
	host_ip(p) != "127.0.0.1"
	msg := sprintf("[GDPR Art.32 NET-01] service '%s' publishes %v on all interfaces (NĐ 13/2023 Đ.26; Luật ATTTM 2015 Đ.19)", [name, p])
}

deny contains msg if {
	some name, svc in input.services
	svc.privileged == true
	msg := sprintf("[CIS Docker 5.4] service '%s' runs privileged", [name])
}

deny contains msg if {
	some name, svc in input.services
	some v in object.get(svc, "volumes", [])
	contains(sprintf("%v", [v]), "docker.sock")
	msg := sprintf("[CIS Docker 5.31] service '%s' mounts the Docker socket", [name])
}

# Biến môi trường có thể là danh sách "KEY=value" hoặc map {KEY: value}; *_FILE trỏ tới secret thì được phép.
env(svc) := [e | some e in svc.environment] if is_array(svc.environment)

env(svc) := [sprintf("%s=%v", [k, v]) | some k, v in svc.environment] if is_object(svc.environment)

env(svc) := [] if not svc.environment

deny contains msg if {
	some name, svc in input.services
	some e in env(svc)
	regex.match(`(?i)^[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY)=.+`, e)
	msg := sprintf("[PCI-DSS 8.2.1 / GDPR Art.32 / NĐ 13/2023 Đ.26] service '%s' has an inline secret in environment: %s", [name, split(e, "=")[0]])
}

drops_all_caps(svc) if "ALL" in object.get(svc, "cap_drop", [])

warn contains msg if {
	some name, svc in input.services
	not drops_all_caps(svc)
	msg := sprintf("[CIS Docker 5.3] service '%s' does not drop capabilities", [name])
}

warn contains msg if {
	some name, svc in input.services
	not svc.read_only
	msg := sprintf("[CIS Docker 5.12] service '%s' has a writable root filesystem", [name])
}
