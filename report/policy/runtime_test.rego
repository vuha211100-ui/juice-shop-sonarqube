package runtime
import rego.v1

good := {"Config": {"User": "65532", "Labels": {"lab.exposure": "edge"}}, "HostConfig": {
    "NanoCpus": 750000000, "PidsLimit": 256, "Privileged": false,
    "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
    "PortBindings": {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3101"}]}}}

test_hardened_passes if { count(deny) == 0 with input as good }
test_memory_not_required if {
    count(deny) == 0 with input as object.union(good, {"HostConfig": object.union(good.HostConfig, {"Memory": 0})})
}
test_default_container_fails if {
    count(deny) == 6 with input as {"Config": {"User": ""}, "HostConfig": {"PortBindings": {"3000/tcp": [{"HostIp": "127.0.0.1"}]}}}
}
test_null_pids_fails if {
    some msg in deny with input as object.union(good, {"HostConfig": object.union(good.HostConfig, {"PidsLimit": null})})
    startswith(msg, "RES-03")
}
test_all_interfaces_port_fails if {
    some msg in deny with input as object.union(good, {"HostConfig": object.union(good.HostConfig, {"PortBindings": {"3000/tcp": [{"HostIp": "", "HostPort": "3000"}]}})})
    startswith(msg, "NET-01")
}

test_backend_with_host_port_denied if {
    some msg in deny with input as object.union(good, {"Config": {"User": "65532", "Labels": {"lab.exposure": "internal"}}})
    startswith(msg, "F03 NET-02")
}
test_backend_without_host_port_passes if {
    count(deny) == 0 with input as {"Config": {"User": "65532", "Labels": {"lab.exposure": "internal"}},
        "HostConfig": object.remove(good.HostConfig, ["PortBindings"])}
}
