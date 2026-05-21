// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

type Config struct {
	Cluster      Cluster      `yaml:"cluster"      validate:"required"`
	ControlPlane ControlPlane `yaml:"controlplane" validate:"required"`
	Worker       Worker       `yaml:"worker"`
}

type Cluster struct {
	Name         string        `yaml:"name"          validate:"required"`
	Domain       string        `yaml:"domain"`
	Secrets      string        `yaml:"secrets"       validate:"required,file"`
	Cilium       *CiliumConfig `yaml:"cilium"        validate:"omitempty"`
	SOPS         *SOPS         `yaml:"sops"          validate:"omitempty"`
	Flux         *Flux         `yaml:"flux"          validate:"omitempty"`
	Image        string        `yaml:"image"`
	Patches      []string      `yaml:"patches"       validate:"omitempty,unique,dive,required"`
	ManifestsPre string        `yaml:"manifests-pre" validate:"omitempty,dir"`
	Manifests    string        `yaml:"manifests"     validate:"omitempty,dir"`
}

type CiliumConfig struct {
	Metrics       *CiliumMetrics       `yaml:"metrics"        validate:"omitempty"`
	Hubble        *CiliumHubble        `yaml:"hubble"         validate:"omitempty"`
	Hardening     *CiliumHardening     `yaml:"hardening"      validate:"omitempty"`
	GatewayAPI    *CiliumGatewayAPI    `yaml:"gateway-api"    validate:"omitempty"`
	NodeIPAM      *CiliumNodeIPAM      `yaml:"node-ipam"      validate:"omitempty"`
	NativeRouting *CiliumNativeRouting `yaml:"native-routing" validate:"omitempty"`
	Netkit        bool                 `yaml:"netkit"`
	BGP           *CiliumBGP           `yaml:"bgp"            validate:"omitempty"`
	Masquerade    *CiliumMasquerade    `yaml:"masquerade"     validate:"omitempty"`
}

type CiliumMetrics struct {
	Enabled        bool `yaml:"enabled"`
	ServiceMonitor bool `yaml:"servicemonitor"`
}

type CiliumHubble struct {
	Enabled bool                 `yaml:"enabled"`
	Metrics *CiliumHubbleMetrics `yaml:"metrics" validate:"omitempty"`
	Export  *CiliumHubbleExport  `yaml:"export"  validate:"omitempty"`
}

type CiliumHubbleMetrics struct {
	Enabled        bool `yaml:"enabled"`
	ServiceMonitor bool `yaml:"servicemonitor"`
}

type CiliumHubbleExport struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path" validate:"required"`
}

type CiliumHardening struct {
	Enabled   bool `yaml:"enabled"`
	AuditMode bool `yaml:"audit-mode"`
}

type CiliumGatewayAPI struct {
	Enabled         bool `yaml:"enabled"`
	HostNetwork     bool `yaml:"host-network"`
	PrivilegedPorts bool `yaml:"privileged-ports"`
}

type CiliumNodeIPAM struct {
	Enabled bool `yaml:"enabled"`
}

type CiliumNativeRouting struct {
	Enabled      bool   `yaml:"enabled"`
	IPv4CIDR     string `yaml:"ipv4-cidr"     validate:"required,cidr"`
	DirectRoutes bool   `yaml:"direct-routes"`
}

type CiliumBGP struct {
	Enabled bool `yaml:"enabled"`
}

type CiliumMasquerade struct {
	Enabled bool  `yaml:"enabled"`
	BPF     *bool `yaml:"bpf"`
}

type SOPS struct {
	GPG string `yaml:"gpg"`
	Age string `yaml:"age" validate:"omitempty,file"`
}

type Flux struct {
	Components      string `yaml:"components"`
	ComponentsExtra string `yaml:"components-extra"`
	AllNamespaces   *bool  `yaml:"all-namespaces"`
	NetworkPolicy   *bool  `yaml:"network-policy"`
}

type ControlPlane struct {
	Record           string              `yaml:"record"`
	RecordAsEndpoint bool                `yaml:"record-as-endpoint"`
	Patches          []string            `yaml:"patches" validate:"omitempty,unique,dive,required"`
	Nodes            map[string][]string `yaml:"nodes"   validate:"required,min=1,dive,unique"`
}

type Worker struct {
	Patches []string            `yaml:"patches" validate:"omitempty,unique,dive,required"`
	Nodes   map[string][]string `yaml:"nodes"   validate:"omitempty,dive,unique"`
}

func (c *CiliumMasquerade) BPFEnabled() bool {
	if c.BPF == nil {
		return true
	}
	return *c.BPF
}

func (f *Flux) AllNamespacesEnabled() bool {
	if f.AllNamespaces == nil {
		return true
	}
	return *f.AllNamespaces
}

func (f *Flux) NetworkPolicyEnabled() bool {
	if f.NetworkPolicy == nil {
		return true
	}
	return *f.NetworkPolicy
}
