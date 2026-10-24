package main

import rego.v1

# F04: chỉ stage CUỐI tạo ra image chạy thật. USER ở stage builder không áp dụng cho stage runtime,
# nên chỉ xét các lệnh USER thuộc stage có chỉ số lớn nhất (bản cũ lấy USER cuối của cả file -> bỏ lọt).
final_stage := max([ins.Stage | some ins in input])

runtime_users := [ins.Value[0] | some ins in input; ins.Stage == final_stage; ins.Cmd == "user"]

last_user := runtime_users[count(runtime_users) - 1] if count(runtime_users) > 0

root_names := {"root", "0"}

# R1 - PCI-DSS 2.2.x / CIS Docker 4.1: the final stage must set USER
deny contains msg if {
	count(runtime_users) == 0
	msg := "[PCI-DSS 2.2 / CIS Docker 4.1] Final build stage has no USER instruction; container will run as root."
}

# R2 - runtime user must not be root (handles "root", "0", "root:root", "0:0")
deny contains msg if {
	last_user
	split(last_user, ":")[0] in root_names
	msg := sprintf("[PCI-DSS 2.2 / CIS Docker 4.1] Final USER is '%s' (root).", [last_user])
}

# R3 - no secrets baked into ENV / ARG
secret_pattern := `(?i)(password|passwd|secret|api[_-]?key|token)`

deny contains msg if {
	some ins in input
	ins.Cmd in {"env", "arg"}
	some v in ins.Value
	regex.match(secret_pattern, v)
	msg := sprintf("[PCI-DSS 8.3 / GDPR Art.32] Possible secret in %s instruction: %s", [upper(ins.Cmd), v])
}

# R4 - no admin/DB ports exposed
admin_ports := {"22", "3306", "5432", "27017", "6379"}

deny contains msg if {
	some ins in input
	ins.Cmd == "expose"
	some p in ins.Value
	split(p, "/")[0] in admin_ports
	msg := sprintf("[GDPR Art.32 / CIS Docker 5.8] Management/DB port %s exposed.", [p])
}

# R5 - unpinned base image (warn only)
warn contains msg if {
	some ins in input
	ins.Cmd == "from"
	img := ins.Value[0]
	endswith(img, ":latest")
	msg := sprintf("[CIS Docker 4.x] Base image '%s' uses :latest; pin a version or digest.", [img])
}

# R6 - HEALTHCHECK recommended (warn only)
warn contains msg if {
	not any_healthcheck
	msg := "[CIS Docker 4.6] No HEALTHCHECK instruction."
}

any_healthcheck if {
	some ins in input
	ins.Cmd == "healthcheck"
}
