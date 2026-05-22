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
	Cilium       *CiliumConfig `yaml:"cilium"`
	SOPS         *SOPS         `yaml:"sops"`
	Flux         *Flux         `yaml:"flux"`
	Image        string        `yaml:"image"`
	Patches      []string      `yaml:"patches"       validate:"omitempty,unique,dive,required"`
	ManifestsPre string        `yaml:"manifests-pre" validate:"omitempty,dir"`
	Manifests    string        `yaml:"manifests"     validate:"omitempty,dir"`
}

type CiliumConfig struct {
	Metrics       *CiliumMetrics       `yaml:"metrics"`
	Hubble        *CiliumHubble        `yaml:"hubble"`
	Hardening     *CiliumHardening     `yaml:"hardening"`
	GatewayAPI    *CiliumGatewayAPI    `yaml:"gateway-api"`
	NodeIPAM      *CiliumNodeIPAM      `yaml:"node-ipam"`
	NativeRouting *CiliumNativeRouting `yaml:"native-routing"`
	Netkit        bool                 `yaml:"netkit"`
	BGP           *CiliumBGP           `yaml:"bgp"`
	Masquerade    *CiliumMasquerade    `yaml:"masquerade"`
}

type CiliumMetrics struct {
	Enabled        bool `yaml:"enabled"`
	ServiceMonitor bool `yaml:"servicemonitor"`
}

type CiliumHubble struct {
	Enabled bool                 `yaml:"enabled"`
	Metrics *CiliumHubbleMetrics `yaml:"metrics"`
	Export  *CiliumHubbleExport  `yaml:"export"`
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
	// Version pins a specific gateway-api release (e.g. "v1.4.0"). When empty
	// the release is auto-resolved from Cilium's go.mod via GitHub. Set this
	// for air-gapped clusters or to lock the bundle for reproducibility.
	Version string `yaml:"version"`
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
	GPG string `yaml:"gpg" validate:"required_without=Age"`
	Age string `yaml:"age" validate:"required_without=GPG,omitempty,file"`
}

type Flux struct {
	Components      string `yaml:"components"`
	ComponentsExtra string `yaml:"components-extra"`
	AllNamespaces   *bool  `yaml:"all-namespaces"`
	NetworkPolicy   *bool  `yaml:"network-policy"`
}

type ControlPlane struct {
	Record           string              `yaml:"record"             validate:"required_if=RecordAsEndpoint true"`
	RecordAsEndpoint bool                `yaml:"record-as-endpoint"`
	Patches          []string            `yaml:"patches"            validate:"omitempty,unique,dive,required"`
	Nodes            map[string][]string `yaml:"nodes"              validate:"required,min=1,dive,unique"`
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
