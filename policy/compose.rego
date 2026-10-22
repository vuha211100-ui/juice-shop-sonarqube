package compose

import rego.v1

# Input: docker-compose.yml (conftest parses YAML natively)
deny contains msg if {
	some name, svc in input.services
	svc.privileged == true
	msg := sprintf("[CIS Docker 5.4] service '%s' runs privileged", [name])
}

deny contains msg if {
	some name, svc in input.services
	some v in svc.volumes
	contains(v, "docker.sock")
	msg := sprintf("[CIS Docker 5.31] service '%s' mounts the Docker socket", [name])
}

deny contains msg if {
	some name, svc in input.services
	some p in svc.ports
	not startswith(p, "127.0.0.1:")
	contains(p, "5432")
	msg := sprintf("[GDPR Art.32] service '%s' publishes DB port %s on all interfaces", [name, p])
}

deny contains msg if {
	some name, svc in input.services
	some e in svc.environment
	regex.match(`(?i)(password|secret|token|key)=.+`, e)
	msg := sprintf("[PCI-DSS 8.3 / GDPR Art.32] service '%s' has an inline secret in environment: %s", [name, split(e, "=")[0]])
}

warn contains msg if {
	some name, svc in input.services
	not svc.read_only
	msg := sprintf("[CIS Docker 5.12] service '%s' has a writable root filesystem", [name])
}

# Sửa so với guide: `not "ALL" in svc.cap_drop` không bao giờ đúng khi thiếu cap_drop,
# nên cảnh báo bị bỏ qua âm thầm. Tách thành rule phụ để `not` hoạt động đúng.
drops_all_caps(svc) if "ALL" in svc.cap_drop

warn contains msg if {
	some name, svc in input.services
	not drops_all_caps(svc)
	msg := sprintf("[CIS Docker 5.3] service '%s' does not drop capabilities", [name])
}
