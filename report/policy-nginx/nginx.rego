# Policy as Code (tạm) cho deploy/nginx.conf — F03: kiểm soát ở proxy phải chuẩn hóa đường dẫn giống backend.
# Express (backend Juice Shop) định tuyến KHÔNG phân biệt hoa thường và chấp nhận '/' cuối, còn nginx
# 'location =', '^~', '~' và prefix thường đều PHÂN BIỆT hoa thường -> '/METRICS' lọt khỏi luật chặn của proxy.
#   chạy: conftest test deploy/nginx.conf --parser nginx -p report/policy-nginx --namespace nginx
# Input (parser nginx): {"directives": [{"name", "parameters", "block": {"directives": [...]}}]}
package nginx

import rego.v1

# Route nhạy cảm proxy phải kiểm soát (F03: chặn /metrics, giới hạn tốc độ đăng nhập)
sensitive := {"/metrics", "/rest/user/login"}

# Mọi chỉ thị location, ở bất kỳ độ sâu nào (http > server > location)
locations contains params if {
	walk(input, [_, node])
	is_object(node)
	node.name == "location"
	params := node.parameters
}

# 'location ~* <regex>' bao phủ route s nếu regex khớp s ở mọi kiểu hoa thường
covers_ci(s) if {
	some params in locations
	params[0] == "~*"
	regex.match(concat("", ["(?i)", params[1]]), s)
}

# Đường dẫn của một location phân biệt hoa thường: '= /x', '^~ /x', '~ regex', hoặc prefix '/x'
cs_target(params) := params[1] if params[0] in {"=", "^~"}

cs_target(params) := params[0] if {
	count(params) == 1
	startswith(params[0], "/")
}

trim_slash(p) := trim_right(p, "/") if p != "/"

deny contains msg if {
	some params in locations
	route := trim_slash(cs_target(params))
	route in sensitive
	not covers_ci(route)
	msg := sprintf("[F03 NGINX-01] location '%s' so khớp PHÂN BIỆT hoa thường, backend Express KHÔNG phân biệt -> '%s' vượt luật proxy; dùng 'location ~* ^%s(/|$)'", [concat(" ", params), upper(route), route])
}

deny contains msg if {
	some params in locations
	params[0] == "~"
	some s in sensitive
	regex.match(params[1], s)
	not covers_ci(s)
	msg := sprintf("[F03 NGINX-01] location '~ %s' là regex PHÂN BIỆT hoa thường cho route nhạy cảm '%s'; dùng '~*'", [params[1], s])
}

# Route nhạy cảm không có location nào kiểm soát -> đi thẳng vào backend qua 'location /'
deny contains msg if {
	some s in sensitive
	not covers_ci(s)
	not cs_controlled(s)
	msg := sprintf("[F03 NGINX-02] route nhạy cảm '%s' không có location riêng ở proxy", [s])
}

cs_controlled(s) if {
	some params in locations
	trim_slash(cs_target(params)) == s
}

cs_controlled(s) if {
	some params in locations
	params[0] == "~"
	regex.match(params[1], s)
}
