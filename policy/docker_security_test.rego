# 13 unit test cho docker_security.rego — bám theo lab ConfTest (mục "unit tests covering the bypasses"),
# bổ sung ca root kèm group (USER 0:1000 / root:1000) để bịt lỗ tách UID.
# chạy: conftest verify -p policy/
package dockerfile

import rego.v1

good := [
	{"Stage": 0, "Cmd": "from", "Value": ["node:24", "AS", "installer"]},
	{"Stage": 1, "Cmd": "from", "Value": ["gcr.io/distroless/nodejs24-debian13"]},
	{"Stage": 1, "Cmd": "label", "Value": ["org.opencontainers.image.source", "https://github.com/juice-shop/juice-shop", "org.opencontainers.image.revision", "abc"]},
	{"Stage": 1, "Cmd": "user", "Value": ["65532"]},
	{"Stage": 1, "Cmd": "expose", "Value": ["3000"]},
	{"Stage": 1, "Cmd": "env", "Value": ["NODE_ENV", "production", "="]},
]

test_good_dockerfile_passes if {
	count(deny) == 0 with input as good
}

test_missing_user_denied if {
	some m in deny with input as array.slice(good, 0, 1)
	contains(m, "no explicit USER")
}

test_root_user_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "user", "Value": ["root"]}]
	contains(m, "runs as root")
}

test_root_uid_zero_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "user", "Value": ["0:0"]}]
	contains(m, "runs as root")
}

# Root UID kèm group khác 0 (USER 0:1000) trước đây lọt vì so khớp nguyên chuỗi; nay phải bị chặn.
test_root_uid_with_nonzero_group_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "user", "Value": ["0:1000"]}]
	contains(m, "runs as root")
}

test_root_name_with_group_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "user", "Value": ["root:1000"]}]
	contains(m, "runs as root")
}

# USER ở stage builder KHÔNG áp dụng cho stage cuối -> vẫn phải bị chặn (bypass chính của lab)
test_builder_user_does_not_cover_final if {
	some m in deny with input as [
		{"Stage": 0, "Cmd": "from", "Value": ["node:24"]},
		{"Stage": 0, "Cmd": "user", "Value": ["10001"]},
		{"Stage": 1, "Cmd": "from", "Value": ["node:24"]},
	]
	contains(m, "no explicit USER")
}

test_forbidden_port_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "expose", "Value": ["3000", "22"]}]
	contains(m, "port 22")
}

test_forbidden_port_with_proto_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "expose", "Value": ["3306/tcp"]}]
	contains(m, "port 3306")
}

test_missing_provenance_label_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "user", "Value": ["65532"]}, {"Stage": 0, "Cmd": "expose", "Value": ["3000"]}]
	contains(m, "org.opencontainers.image.source")
}

test_add_instruction_denied if {
	some m in deny with input as array.concat(good, [{"Stage": 1, "Cmd": "add", "Value": ["http://x/y", "/y"]}])
	contains(m, "use COPY instead of ADD")
}

# SECRET-IN-IMAGE (cải tiến của nhóm ngoài bản mẫu lab)
test_secret_env_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "env", "Value": ["API_TOKEN", "abc123", "="]}]
	contains(m, "SECRET-IN-IMAGE")
}

test_secret_arg_denied if {
	some m in deny with input as [{"Stage": 0, "Cmd": "arg", "Value": ["DB_PASSWORD=p@ss"]}]
	contains(m, "SECRET-IN-IMAGE")
}
