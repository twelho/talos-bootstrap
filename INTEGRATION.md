# Downstream integration requirements

`talos-bootstrap` is consumed by external GitOps repos that adopt the
bootstrap-installed Cilium release under Flux and apply additional
manifests on top. This document describes two changes the downstream
needs from upstream to make that handoff clean.

The downstream contract is:

1. `bootstrap cilium values <config>` renders the Helm values
   downstream applies to the adopted `cilium/cilium` release. Output
   must be consumable verbatim, without re-introducing
   `trustCRDsExist` or other "look the other way" overrides.
2. A new `bootstrap facts <config>` subcommand emits the small set of
   cluster facts the downstream repo needs to template against, so
   those facts do not have to be re-encoded by hand on the consumer
   side and drift away from the bootstrap config.

## 1. Robust ServiceMonitor CRD handling

### Problem

When `cluster.cilium.metrics.servicemonitor: true` (or the matching
Hubble flag) is set, the Cilium chart's
[`templates/validate.yaml`](https://github.com/cilium/cilium/blob/main/install/kubernetes/cilium/templates/validate.yaml)
fails at render time if the `monitoring.coreos.com/v1`
`ServiceMonitor` CRD is not present on the cluster. The workaround on
the consumer side is to set `serviceMonitor.trustCRDsExist: true` in
the Flux `HelmRelease` values — which forks the values from what
`bootstrap cilium values` emits and removes the rendered output's
value as a source-of-truth contract.

Today this happens transparently in `phaseCilium` because Talos
clusters bootstrap before the monitoring stack lands, so the CRD is
genuinely absent. The downstream then carries a manual override
forever.

### Required change

Install the `ServiceMonitor` (and `PodMonitor`, used by Hubble
metrics) CRDs as a bootstrap phase, mirroring how
`phaseGatewayCRDs` handles Gateway API CRDs today
([internal/gateway/gateway.go](internal/gateway/gateway.go),
[internal/bootstrap/phases.go:271](internal/bootstrap/phases.go)).

Shape:

- New package `internal/monitoring` with an `InstallCRDs(ctx, kube,
  version)` that downloads the prometheus-operator stripped CRD
  bundle (e.g.
  `https://github.com/prometheus-operator/prometheus-operator/releases/download/<tag>/stripped-down-crds.yaml`,
  or just the two CRDs we need) and server-side applies it.
- Version resolution: a fixed pin in the package is fine — the
  prometheus-operator CRD surface is very stable and unlike Gateway
  API there is no upstream coupling to Cilium's go.mod. A `latest
  stable release tag` lookup against the GitHub releases API is
  acceptable too; reuse the `httpGet` helper from
  `internal/gateway`.
- New phase `phaseMonitoringCRDs` that runs **before** `phaseCilium`
  (the validate template runs at Helm render time, so the CRDs must
  exist before any Cilium chart install — including the operator-only
  pre-CNI install in `phaseCilium` when `manifests-pre` is set).
- Gate the phase on
  `ciliumOpts.Metrics != nil && ciliumOpts.Metrics.ServiceMonitor`
  OR
  `ciliumOpts.Hubble != nil && ciliumOpts.Hubble.Metrics != nil && ciliumOpts.Hubble.Metrics.ServiceMonitor`.
  If neither is set, skip entirely.
- After apply, wait for `servicemonitors.monitoring.coreos.com` (and
  `podmonitors.monitoring.coreos.com` if installed) via
  `kube.WaitCRDEstablished`.

### Consequence for `cilium values` output

Once the CRDs are guaranteed present at install time, the rendered
values from `bootstrap cilium values` no longer need any consumer-side
overlay for the metrics path. The downstream Flux `HelmRelease` can
consume the rendered file verbatim.

No schema change is required for the cluster config — the existing
`metrics.servicemonitor` / `hubble.metrics.servicemonitor` toggles
already drive the new phase.

### Notes

- The downstream eventually installs a full
  `kube-prometheus-stack` (or equivalent) via Flux, which ships its
  own copy of these CRDs. Server-side apply with bootstrap as the
  field manager and the operator chart as a second field manager
  coexists fine in practice; the operator chart should be configured
  with `crds.enabled: false` downstream, or accept that the CRD
  object is co-owned.
- Restart of the Cilium agent after CRD install is **not** required
  (unlike Gateway API, where the operator needs a restart to pick up
  the new CRDs). The agent only reads these CRDs to create
  ServiceMonitor objects, which it does on the next reconcile.

## 2. `bootstrap facts` subcommand

### Problem

Downstream repos (currently the `cracicorp/infra` Nix flake) need a
small handful of facts from the bootstrap config to template against
— cluster name, domain, native-routing CIDR, control plane endpoint.
Today these are re-encoded as literals on the consumer side, which
drifts whenever the bootstrap YAML changes. There is no need for the
downstream to parse the full bootstrap schema — only the shared facts
matter.

### Required change

New subcommand `bootstrap facts <config>` that emits a stable JSON
document on stdout. JSON (not YAML) because Nix has built-in
`fromJSON` and we want consumers to read it without IFD-ing a YAML
converter.

Suggested layout — keys are stable, additive changes only, breaking
changes require bumping `schemaVersion`:


Implementation:

- New package `internal/facts` with a `Facts` struct and a `From(cfg
  *config.Config) Facts` constructor.
- New CLI file `cmd/bootstrap/cli/facts.go` modeled on
  `cilium.go`. The command takes the cluster config path, calls
  `config.Load`, calls `facts.From`, writes
  `json.MarshalIndent(facts, "", "  ")` to stdout.
- Treat the JSON output as the contract: cover the shape with a
  golden-file test in `internal/facts` so refactors cannot
  accidentally rename keys.

### Notes

- `controlPlane.endpoint` is derived: when
  `controlplane.record-as-endpoint: true`, use
  `<record>.<domain>:6443`; otherwise pick the first control plane
  node's FQDN with `:6443`. The downstream uses this for the
  generated kubeconfig and any out-of-cluster API client config.
- Omit `secrets:` paths, GPG fingerprints, and any other field that
  is sensitive or local-filesystem-relative. The facts file is meant
  to be safe to commit / publish.
- `features.*` is the subset of `cluster.cilium.*` toggles that
  downstream gates on (e.g. "if `bgp` is true, render the BGP
  policies bundle"). Add more entries here as new gates arise rather
  than asking consumers to re-parse the Cilium block.

## Out of scope

- No change to the `cluster.cilium.*` schema, the Cilium values
  renderer, or the existing phase ordering beyond inserting
  `phaseMonitoringCRDs` before `phaseCilium`.
- No change to the bootstrap binary's external dependencies beyond
  one additional HTTPS fetch at bootstrap time (the
  prometheus-operator CRD bundle).
- The `facts` subcommand is read-only and side-effect free; it does
  not touch the cluster or the network.
