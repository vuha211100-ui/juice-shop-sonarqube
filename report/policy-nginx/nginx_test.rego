# Unit test cho nginx.rego. chạy: conftest verify -p report/policy-nginx
package nginx

import rego.v1

server(locs) := {"directives": [{"name": "http", "block": {"directives": [{"name": "server", "block": {"directives": locs}}]}}]}

loc(params) := {"name": "location", "parameters": params, "block": {"directives": []}}

# Cấu hình trước khi sửa: '= /metrics', '^~ /metrics/', '= /rest/user/login' -> 3 vi phạm
before := server([loc(["=", "/metrics"]), loc(["^~", "/metrics/"]), loc(["=", "/rest/user/login"]), loc(["/"])])

# Cấu hình đã sửa: regex không phân biệt hoa thường
after := server([loc(["~*", "^/metrics(/|$)"]), loc(["~*", "^/rest/user/login/?$"]), loc(["/"])])

test_case_sensitive_locations_denied if {
	count(deny) == 3 with input as before
}

test_case_insensitive_locations_pass if {
	count(deny) == 0 with input as after
}

test_case_sensitive_regex_denied if {
	some m in deny with input as server([loc(["~", "^/metrics"]), loc(["~*", "^/rest/user/login/?$"])])
	contains(m, "'~ ^/metrics'")
}

test_missing_location_denied if {
	some m in deny with input as server([loc(["~*", "^/metrics(/|$)"]), loc(["/"])])
	contains(m, "NGINX-02")
}
