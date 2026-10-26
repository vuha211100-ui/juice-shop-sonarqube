package runtime
import rego.v1

# v3: bỏ luật bắt buộc giới hạn RAM (RES-01) theo phạm vi báo cáo; bổ sung các luật đặc quyền/mạng.
deny contains "RES-02: CPU quota must be bounded" if {
    object.get(input.HostConfig, "NanoCpus", 0) <= 0
}
deny contains "RES-03: PID count must be bounded" if {
    not object.get(input.HostConfig, "PidsLimit", null) > 0
}
deny contains "PRIV-01: privileged container forbidden" if { input.HostConfig.Privileged == true }
deny contains "PRIV-02: explicit numeric non-root UID required" if {
    not regex.match(`^[1-9][0-9]*(:[0-9]+)?$`, object.get(input.Config, "User", ""))
}
deny contains "PRIV-03: all Linux capabilities must be dropped" if {
    not "ALL" in object.get(input.HostConfig, "CapDrop", [])
}
deny contains "PRIV-04: no-new-privileges must be set" if {
    not "no-new-privileges:true" in object.get(input.HostConfig, "SecurityOpt", [])
}
deny contains msg if {
    some port, binds in object.get(input.HostConfig, "PortBindings", {})
    some b in binds
    b.HostIp != "127.0.0.1"
    msg := sprintf("NET-01: port %s is published on '%s', only 127.0.0.1 is allowed", [port, b.HostIp])
}

# F03 / NET-02 (runtime): chỉ container gắn nhãn lab.exposure=edge (proxy, dashboard) được có cổng trên host.
# Labels có thể thiếu hoặc null trong docker inspect: lấy bằng object.get để luôn có giá trị.
labels := object.get(object.get(input, "Config", {}), "Labels", {})

exposure := object.get(labels, "lab.exposure", "") if is_object(labels)

exposure := "" if not is_object(labels)

deny contains msg if {
    exposure != "edge"
    some port, binds in object.get(input.HostConfig, "PortBindings", {})
    count(binds) > 0
    msg := sprintf("F03 NET-02: non-edge container publishes %s to the host", [port])
}
