// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cilium

import (
	"slices"

	"sigs.k8s.io/yaml"

	"github.com/twelho/talos-bootstrap/internal/config"
)

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

// valuesBuilder accumulates the Helm values map together with the capability
// sets that some features (BGP, Gateway API privileged ports) extend. Every
// apply* method mutates the builder; rendering is one linear pass.
type valuesBuilder struct {
	v         map[string]any
	agentCaps []string
	envoyCaps []string
}

// Values renders Options into the nested map structure that the Cilium Helm
// chart consumes. agent=false leaves the agent DaemonSet out of the install,
// which is required for the pre-CNI bootstrap of CRDs without exposing the
// cluster to a half-configured policy enforcer.
func (o Options) Values(agent bool) map[string]any {
	b := &valuesBuilder{
		v: map[string]any{
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
		},
		agentCaps: slices.Clone(defaultAgentCapabilities),
		envoyCaps: slices.Clone(defaultEnvoyCapabilities),
	}

	if o.singleOperator() {
		b.set([]string{"operator", "replicas"}, 1)
	}

	c := o.Cilium
	o.applyMetrics(b, c)
	o.applyHubble(b, c)
	o.applyHardening(b)
	o.applyNativeRouting(b, c)
	o.applyNetkit(b, c)
	o.applyBGP(b, c)
	o.applyMasquerade(b, c)
	o.applyNodeIPAM(b, c)
	o.applyGatewayAPI(b)

	b.set([]string{"securityContext", "capabilities", "ciliumAgent"}, b.agentCaps)
	b.set([]string{"securityContext", "capabilities", "cleanCiliumState"}, defaultCleanStateCapabilities)
	b.set([]string{"envoy", "securityContext", "capabilities", "envoy"}, b.envoyCaps)

	return b.v
}

// ValuesYAML renders Options to a YAML document suitable for `helm install -f`
// or for handoff to external consumers.
func (o Options) ValuesYAML(agent bool) ([]byte, error) {
	return yaml.Marshal(o.Values(agent))
}

func (Options) applyMetrics(b *valuesBuilder, c *config.CiliumConfig) {
	if c == nil || c.Metrics == nil {
		return
	}
	en := c.Metrics.Enabled
	b.set([]string{"prometheus", "enabled"}, en)
	b.set([]string{"operator", "prometheus", "enabled"}, en)
	if !en {
		return
	}
	sm := c.Metrics.ServiceMonitor
	b.set([]string{"prometheus", "serviceMonitor", "enabled"}, sm)
	b.set([]string{"envoy", "prometheus", "serviceMonitor", "enabled"}, sm)
	b.set([]string{"operator", "prometheus", "serviceMonitor", "enabled"}, sm)
	// Hubble's metrics block is owned by applyHubble: only render the
	// serviceMonitor child here if the user actually opted into Hubble.
	if c.Hubble != nil {
		b.set([]string{"hubble", "metrics", "serviceMonitor", "enabled"}, sm)
	}
}

func (Options) applyHubble(b *valuesBuilder, c *config.CiliumConfig) {
	if c == nil || c.Hubble == nil {
		return
	}
	b.set([]string{"hubble", "enabled"}, c.Hubble.Enabled)
	b.set([]string{"hubble", "ui", "enabled"}, c.Hubble.Enabled)
	b.set([]string{"hubble", "relay", "enabled"}, c.Hubble.Enabled)

	if c.Hubble.Metrics != nil && c.Hubble.Metrics.Enabled {
		b.set([]string{"hubble", "metrics", "enableOpenMetrics"}, true)
		b.set([]string{"hubble", "metrics", "enabled"}, []string{
			"dns", "drop", "flow", "flows-to-world", "icmp",
			"port-distribution", "tcp", hubbleHTTPv2Metric,
		})
		b.set([]string{"hubble", "metrics", "serviceMonitor", "enabled"},
			c.Hubble.Metrics.ServiceMonitor)
	}

	if c.Hubble.Export != nil {
		b.set([]string{"hubble", "export", "static", "enabled"}, c.Hubble.Export.Enabled)
		b.set([]string{"hubble", "export", "static", "filePath"}, c.Hubble.Export.Path)
	}
}

func (o Options) applyHardening(b *valuesBuilder) {
	if o.hardeningEnabled() {
		b.v["policyEnforcementMode"] = "always"
		b.set([]string{"hostFirewall", "enabled"}, true)
		b.set([]string{"extraConfig", "allow-localhost"}, "policy")
		// Helm requires this be a string, not a bool, so it can pass through
		// to the agent's --set-string equivalent.
		b.set([]string{"extraConfig", "enable-node-selector-labels"}, "true")
	}
	if o.hardeningAuditMode() {
		b.v["policyAuditMode"] = true
	}
}

func (Options) applyNativeRouting(b *valuesBuilder, c *config.CiliumConfig) {
	if c == nil || c.NativeRouting == nil || !c.NativeRouting.Enabled {
		return
	}
	b.v["routingMode"] = "native"
	b.v["ipv4NativeRoutingCIDR"] = c.NativeRouting.IPv4CIDR
	b.v["autoDirectNodeRoutes"] = c.NativeRouting.DirectRoutes
}

func (Options) applyNetkit(b *valuesBuilder, c *config.CiliumConfig) {
	if c == nil || !c.Netkit {
		return
	}
	b.set([]string{"bpf", "datapathMode"}, "netkit")
}

func (Options) applyBGP(b *valuesBuilder, c *config.CiliumConfig) {
	if c == nil || c.BGP == nil || !c.BGP.Enabled {
		return
	}
	b.set([]string{"bgpControlPlane", "enabled"}, true)
	b.agentCaps = append(b.agentCaps, "NET_BIND_SERVICE")
}

func (Options) applyMasquerade(b *valuesBuilder, c *config.CiliumConfig) {
	if c == nil || c.Masquerade == nil {
		return
	}
	if !c.Masquerade.Enabled {
		b.set([]string{"bpf", "masquerade"}, false)
		b.v["enableIPv4Masquerade"] = false
		b.v["enableIPv6Masquerade"] = false
		return
	}
	b.set([]string{"bpf", "masquerade"}, c.Masquerade.BPFEnabled())
}

func (Options) applyNodeIPAM(b *valuesBuilder, c *config.CiliumConfig) {
	if c == nil || c.NodeIPAM == nil || !c.NodeIPAM.Enabled {
		return
	}
	b.set([]string{"nodeIPAM", "enabled"}, true)
}

func (o Options) applyGatewayAPI(b *valuesBuilder) {
	if !o.GatewayAPIEnabled() {
		return
	}
	gw := o.Cilium.GatewayAPI
	b.set([]string{"gatewayAPI", "enabled"}, true)
	b.set([]string{"gatewayAPI", "enableAlpn"}, true)
	b.set([]string{"gatewayAPI", "enableAppProtocol"}, true)
	if gw.HostNetwork {
		b.set([]string{"gatewayAPI", "hostNetwork", "enabled"}, true)
	}
	if gw.PrivilegedPorts {
		b.set([]string{"envoy", "securityContext", "capabilities", "keepCapNetBindService"}, true)
		b.envoyCaps = append(b.envoyCaps, "NET_BIND_SERVICE")
	}
}

// set writes value at the nested map address described by path, creating
// intermediate maps as needed. Panics if an existing intermediate is not a
// map: Values is the sole writer and any conflict would silently lose data.
func (b *valuesBuilder) set(path []string, value any) {
	cur := b.v
	for i, key := range path {
		if i == len(path)-1 {
			cur[key] = value
			return
		}
		next := cur[key]
		if next == nil {
			m := map[string]any{}
			cur[key] = m
			cur = m
			continue
		}
		m, isMap := next.(map[string]any)
		if !isMap {
			panic("cilium values: non-map at " + key)
		}
		cur = m
	}
}
