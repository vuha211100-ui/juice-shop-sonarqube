package main

import rego.v1

# F04: USER chỉ có ở stage builder, stage runtime không có USER -> phải bị chặn (ca từng lọt qua gate)
test_builder_user_does_not_cover_final_stage if {
	some msg in deny with input as [
		{"Stage": 0, "Cmd": "from", "Value": ["alpine:3.20"]},
		{"Stage": 0, "Cmd": "user", "Value": ["10001"]},
		{"Stage": 1, "Cmd": "from", "Value": ["alpine:3.20"]},
		{"Stage": 1, "Cmd": "cmd", "Value": ["true"]},
	]
	contains(msg, "Final build stage has no USER")
}

test_final_stage_non_root_user_passes if {
	count(deny) == 0 with input as [
		{"Stage": 0, "Cmd": "from", "Value": ["node:22"]},
		{"Stage": 1, "Cmd": "from", "Value": ["gcr.io/distroless/nodejs22-debian12"]},
		{"Stage": 1, "Cmd": "user", "Value": ["65532"]},
	]
}

test_final_stage_root_user_denied if {
	some msg in deny with input as [
		{"Stage": 0, "Cmd": "from", "Value": ["alpine:3.20"]},
		{"Stage": 0, "Cmd": "user", "Value": ["root:root"]},
	]
	contains(msg, "(root)")
}

test_last_user_in_final_stage_wins if {
	some msg in deny with input as [
		{"Stage": 0, "Cmd": "from", "Value": ["alpine:3.20"]},
		{"Stage": 0, "Cmd": "user", "Value": ["10001"]},
		{"Stage": 0, "Cmd": "user", "Value": ["0"]},
	]
	contains(msg, "(root)")
}
