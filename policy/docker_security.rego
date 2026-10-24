# Policy as Code cho Dockerfile của Juice Shop — bám theo lab môn học "Policy as Code with Conftest".
# Mỗi luật đặt tại điểm thực thi đúng thay vì các "original check" dễ bị qua mặt:
#   Least privilege  -> USER ở STAGE CUỐI, UID số, không phải root (thay vì "có USER bất kỳ trong file")
#   Firewall/RBAC    -> cổng quản trị/DB không được EXPOSE (giảm bề mặt tấn công)
#   MFA/provenance   -> nhãn OCI source + revision (thay vì LABEL mfa="true" tự khai)
#   Logging/observ.  -> HEALTHCHECK ở image chạy thật
#   Supply chain     -> không :latest, không ADD, cảnh báo base image chưa ghim digest
#   chạy: conftest test <Dockerfile> -p policy/ --namespace dockerfile
package dockerfile

import rego.v1

forbidden_ports := {"22", "23", "3306", "5432"}

required_labels := {"org.opencontainers.image.source", "org.opencontainers.image.revision"}

root_names := {"root", "0", "root:root", "0:0"}

# Chỉ STAGE CUỐI tạo ra image chạy thật; USER ở stage builder không áp dụng cho runtime.
final_stage := max([ins.Stage | some ins in input])

final_users := [ins.Value[0] | some ins in input; ins.Stage == final_stage; ins.Cmd == "user"]

last_user := final_users[count(final_users) - 1] if count(final_users) > 0

# LEAST-PRIVILEGE ------------------------------------------------------------
deny contains msg if {
	count(final_users) == 0
	msg := "LEAST-PRIVILEGE: final stage has no USER instruction; container runs as root. (CIS Docker 4.1; PCI-DSS 2.2.6; NIST SP 800-190)"
}

deny contains msg if {
	last_user in root_names
	msg := sprintf("LEAST-PRIVILEGE: final USER '%s' is root. (CIS Docker 4.1; PCI-DSS 2.2.6)", [last_user])
}

warn contains msg if {
	last_user
	not last_user in root_names
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

# PROVENANCE (thay cho MFA label tự khai) -----------------------------------
label_blob := concat(" ", [concat(" ", ins.Value) | some ins in input; ins.Cmd == "label"])

deny contains msg if {
	some req in required_labels
	not contains(label_blob, req)
	msg := sprintf("PROVENANCE: required OCI label '%s' is missing. (OCI image-spec; SLSA Provenance L1; NIST SSDF)", [req])
}

# OBSERVABILITY --------------------------------------------------------------
has_healthcheck if {
	some ins in input
	ins.Cmd == "healthcheck"
	upper(ins.Value[0]) != "NONE"
}

deny contains msg if {
	not has_healthcheck
	msg := "OBSERVABILITY: no HEALTHCHECK in final stage (distroless images need a shell-less check). (CIS Docker 4.6)"
}

# SUPPLY-CHAIN ---------------------------------------------------------------
deny contains msg if {
	some ins in input
	ins.Cmd == "from"
	endswith(ins.Value[0], ":latest")
	msg := sprintf("SUPPLY-CHAIN: base image '%s' uses :latest; pin a version or digest. (CIS Docker 4.5; SLSA)", [ins.Value[0]])
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
	msg := sprintf("SUPPLY-CHAIN: base image '%s' is not pinned by digest. (CIS Docker 4.5; SLSA)", [ins.Value[0]])
}
