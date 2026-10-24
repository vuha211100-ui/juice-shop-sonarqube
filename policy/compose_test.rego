package compose

import rego.v1

backend := {"image": "juice-shop", "cap_drop": ["ALL"], "read_only": true}

proxy := object.union(backend, {"ports": ["127.0.0.1:3102:8080"], "labels": {"lab.exposure": "edge"}})

# F03: cấu hình cũ publish thẳng backend 127.0.0.1:3101 -> phải bị chặn dù đã bind loopback
test_backend_publishing_port_denied if {
	some msg in deny with input as {"services": {"proxy": proxy, "juice-shop": object.union(backend, {"ports": ["127.0.0.1:3101:3000"]})}}
	contains(msg, "F03 NET-02")
}

test_only_proxy_publishes_passes if {
	count(deny) == 0 with input as {"services": {"proxy": proxy, "juice-shop": backend}}
}

test_edge_on_all_interfaces_denied if {
	some msg in deny with input as {"services": {"proxy": object.union(proxy, {"ports": ["3102:8080"]})}}
	contains(msg, "NET-01")
}

test_long_syntax_port_checked if {
	some msg in deny with input as {"services": {"proxy": object.union(proxy, {"ports": [{"target": 8080, "published": 3102}]})}}
	contains(msg, "NET-01")
}

test_inline_secret_in_env_map_denied if {
	some msg in deny with input as {"services": {"db": object.union(backend, {"environment": {"POSTGRES_PASSWORD": "x"}})}}
	contains(msg, "inline secret")
}

test_secret_file_reference_allowed if {
	count(deny) == 0 with input as {"services": {"db": object.union(backend, {"environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/db"}})}}
}
