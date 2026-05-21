// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cilium

import "sigs.k8s.io/yaml"

// Capability sets applied by talos-bootstrap. SYS_MODULE is intentionally
// absent: it is forbidden on Talos. Envoy normally needs SYS_ADMIN, but Cilium
// permits replacing it with PERFMON+BPF (see install/kubernetes/cilium/values.yaml
// in the Cilium repo) which is what we use here.
var (
	defaultAgentCapabilities = []string{
		"CHOWN", "KILL", "NET_ADMIN", "NET_RAW", "IPC_LOCK",
		"SYS_ADMIN", "SYS_RESOURCE",
		"DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "SYSLOG",
	}
	defaultCleanStateCapabilities = []string{"NET_ADMIN", "SYS_ADMIN", "SYS_RESOURCE"}
	defaultEnvoyCapabilities      = []string{"NET_ADMIN", "PERFMON", "BPF"}
)

const hubbleHTTPv2Metric = "httpV2:exemplars=true;labelsContext=" +
	"source_ip,source_namespace,source_workload," +
	"destination_ip,destination_namespace,destination_workload," +
	"traffic_direction"

// Values renders Options into the nested map structure that the Cilium Helm
// chart consumes. agent=false leaves the agent DaemonSet out of the install,
// which is required for the pre-CNI bootstrap of CRDs without exposing the
// cluster to a half-configured policy enforcer.
func (o Options) Values(agent bool) map[string]any {
	v := map[string]any{
		"agent":                agent,
		"ipam":                 map[string]any{"mode": "kubernetes"},
		"kubeProxyReplacement": true,
		"cgroup": map[string]any{
			"autoMount": map[string]any{"enabled": false},
			"hostRoot":  "/sys/fs/cgroup",
		},
		"k8sServiceHost":    "localhost",
		"k8sServicePort":    7445,
		"rollOutCiliumPods": true,
		"envoy":             map[string]any{"rollOutPods": true},
		"hubble": map[string]any{
			"relay": map[string]any{"rollOutPods": true},
			"ui":    map[string]any{"rollOutPods": true},
		},
		"operator": map[string]any{"rollOutPods": true},
	}

	if o.SingleOperator {
		setPath(v, []string{"operator", "replicas"}, 1)
	}

	agentCaps := append([]string{}, defaultAgentCapabilities...)
	envoyCaps := append([]string{}, defaultEnvoyCapabilities...)

	o.applyMetrics(v)
	o.applyHubble(v)
	o.applyHardening(v)
	o.applyNativeRouting(v)
	o.applyNetkit(v)
	o.applyBGP(v, &agentCaps)
	o.applyMasquerade(v)
	o.applyNodeIPAM(v)
	o.applyGatewayAPI(v, &envoyCaps)

	setPath(v, []string{"securityContext", "capabilities", "ciliumAgent"}, agentCaps)
	setPath(v, []string{"securityContext", "capabilities", "cleanCiliumState"}, defaultCleanStateCapabilities)
	setPath(v, []string{"envoy", "securityContext", "capabilities", "envoy"}, envoyCaps)

	return v
}

// ValuesYAML renders Options to a YAML document suitable for `helm install -f`
// or for handoff to external consumers.
func (o Options) ValuesYAML(agent bool) ([]byte, error) {
	return yaml.Marshal(o.Values(agent))
}

func (o Options) applyMetrics(v map[string]any) {
	if o.Metrics == nil {
		return
	}
	en := o.Metrics.Enabled
	setPath(v, []string{"prometheus", "enabled"}, en)
	setPath(v, []string{"operator", "prometheus", "enabled"}, en)
	if !en {
		return
	}
	sm := o.Metrics.ServiceMonitor
	setPath(v, []string{"hubble", "metrics", "serviceMonitor", "enabled"}, sm)
	setPath(v, []string{"prometheus", "serviceMonitor", "enabled"}, sm)
	setPath(v, []string{"envoy", "prometheus", "serviceMonitor", "enabled"}, sm)
	setPath(v, []string{"operator", "prometheus", "serviceMonitor", "enabled"}, sm)
}

func (o Options) applyHubble(v map[string]any) {
	if o.Hubble == nil {
		return
	}
	setPath(v, []string{"hubble", "enabled"}, o.Hubble.Enabled)
	setPath(v, []string{"hubble", "ui", "enabled"}, o.Hubble.Enabled)
	setPath(v, []string{"hubble", "relay", "enabled"}, o.Hubble.Enabled)

	if o.Hubble.Metrics != nil && o.Hubble.Metrics.Enabled {
		setPath(v, []string{"hubble", "metrics", "enableOpenMetrics"}, true)
		setPath(v, []string{"hubble", "metrics", "enabled"}, []string{
			"dns", "drop", "flow", "flows-to-world", "icmp",
			"port-distribution", "tcp", hubbleHTTPv2Metric,
		})
		setPath(v, []string{"hubble", "metrics", "serviceMonitor", "enabled"},
			o.Hubble.Metrics.ServiceMonitor)
	}

	if o.Hubble.Export != nil {
		setPath(v, []string{"hubble", "export", "static", "enabled"}, o.Hubble.Export.Enabled)
		setPath(v, []string{"hubble", "export", "static", "filePath"}, o.Hubble.Export.Path)
	}
}

func (o Options) applyHardening(v map[string]any) {
	if o.Hardening.Enabled {
		v["policyEnforcementMode"] = "always"
		setPath(v, []string{"hostFirewall", "enabled"}, true)
		setPath(v, []string{"extraConfig", "allow-localhost"}, "policy")
		// Helm requires this be a string, not a bool, so it can pass through
		// to the agent's --set-string equivalent.
		setPath(v, []string{"extraConfig", "enable-node-selector-labels"}, "true")
	}
	if o.Hardening.AuditMode {
		v["policyAuditMode"] = true
	}
}

func (o Options) applyNativeRouting(v map[string]any) {
	if o.NativeRouting == nil || !o.NativeRouting.Enabled {
		return
	}
	v["routingMode"] = "native"
	v["ipv4NativeRoutingCIDR"] = o.NativeRouting.IPv4CIDR
	v["autoDirectNodeRoutes"] = o.NativeRouting.DirectRoutes
}

func (o Options) applyNetkit(v map[string]any) {
	if !o.Netkit {
		return
	}
	setPath(v, []string{"bpf", "datapathMode"}, "netkit")
}

func (o Options) applyBGP(v map[string]any, agentCaps *[]string) {
	if o.BGP == nil || !o.BGP.Enabled {
		return
	}
	setPath(v, []string{"bgpControlPlane", "enabled"}, true)
	*agentCaps = append(*agentCaps, "NET_BIND_SERVICE")
}

func (o Options) applyMasquerade(v map[string]any) {
	if o.Masquerade == nil {
		return
	}
	if o.Masquerade.Enabled {
		setPath(v, []string{"bpf", "masquerade"}, o.Masquerade.BPF)
		return
	}
	setPath(v, []string{"bpf", "masquerade"}, false)
	v["enableIPv4Masquerade"] = false
	v["enableIPv6Masquerade"] = false
}

func (o Options) applyNodeIPAM(v map[string]any) {
	if o.NodeIPAM == nil || !o.NodeIPAM.Enabled {
		return
	}
	setPath(v, []string{"nodeIPAM", "enabled"}, true)
}

func (o Options) applyGatewayAPI(v map[string]any, envoyCaps *[]string) {
	if !o.GatewayAPIEnabled() {
		return
	}
	setPath(v, []string{"gatewayAPI", "enabled"}, true)
	setPath(v, []string{"gatewayAPI", "enableAlpn"}, true)
	setPath(v, []string{"gatewayAPI", "enableAppProtocol"}, true)
	if o.GatewayAPI.HostNetwork {
		setPath(v, []string{"gatewayAPI", "hostNetwork", "enabled"}, true)
	}
	if o.GatewayAPI.PrivilegedPorts {
		setPath(v, []string{"envoy", "securityContext", "capabilities", "keepCapNetBindService"}, true)
		*envoyCaps = append(*envoyCaps, "NET_BIND_SERVICE")
	}
}

// setPath writes v at the nested map address described by path, creating
// intermediate maps as needed. If a non-map value is encountered along the
// way it is replaced; this is fine because Values builds the tree itself
// and there are no callers that rely on overwriting non-maps.
func setPath(root map[string]any, path []string, v any) {
	cur := root
	for i, key := range path {
		if i == len(path)-1 {
			cur[key] = v
			return
		}
		next, ok := cur[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[key] = next
		}
		cur = next
	}
}
