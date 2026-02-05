#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# bootstrap.py - Bootstrap a provisioned Talos Linux cluster.
# (c) Dennis Marttinen, Veeti Poutsalo 2022

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

import gnupg
import requests
import yaml
from schema import And, Optional, Or, Schema, SchemaError

str_schema = And(str, And(len, error="empty strings not allowed"))  # type: ignore
file_schema = And(
    str_schema,  # type: ignore
    And(lambda x: os.path.isfile(x), error="file not found: {}"),  # type: ignore
)
dir_schema = And(
    str_schema,  # type: ignore
    And(lambda x: os.path.isdir(x), error="directory not found: {}"),  # type: ignore
)
patch_schema = And(
    [str],  # type: ignore
    And(lambda x: len(x) == len(set(x)), error="duplicates not allowed: {}"),  # type: ignore
)

# Schema for the bootstrap configuration files
config_schema = Schema(
    {
        "cluster": {
            "name": str_schema,
            Optional("domain"): str_schema,
            "secrets": file_schema,
            Optional("cilium"): {
                Optional("metrics"): bool,
                Optional("hubble"): {
                    "enabled": bool,
                    Optional("metrics"): bool,
                },
                Optional("hardening"): {
                    "enabled": bool,
                    "audit-mode": bool,
                },
                Optional("gateway-api"): {
                    "enabled": bool,
                    Optional("host-network"): bool,
                    Optional("privileged-ports"): bool,
                },
                Optional("native-routing"): {
                    "enabled": bool,
                    "ipv4-cidr": str_schema,
                    "direct-routes": bool,
                },
                Optional("netkit"): bool,
                Optional("bgp"): {
                    "enabled": bool,
                },
                Optional("node-ipam"): {
                    "enabled": bool,
                },
            },
            Optional("sops"): str_schema,
            Optional("flux"): {
                Optional("components"): str_schema,
                Optional("components-extra"): str_schema,
                Optional("all-namespaces"): bool,
                Optional("ssh"): {
                    "url": str_schema,
                    "branch": str_schema,
                    "key": file_schema,
                },
            },
            Optional("image"): str_schema,
            Optional("patches"): patch_schema,
            Optional("manifests"): dir_schema,
        },
        "controlplane": {
            "record": str,
            Optional("record-as-endpoint"): bool,
            Optional("patches"): patch_schema,
            "nodes": {str_schema: Or(patch_schema, None)},  # type: ignore
        },
        "worker": {
            Optional("patches"): patch_schema,
            "nodes": Or({str_schema: Or(patch_schema, None)}, None),  # type: ignore
        },
    }
)


# Key-value input parser for argparse, with optional values
class KeyValueAction(argparse.Action):
    def __call__(self, _, namespace, values, option_string=None):
        current_kv = getattr(namespace, self.dest) or {}
        pairs = [pair.split("=", 1) + [None] for pair in values.split(",")]
        try:
            for key, value, *_ in pairs:
                if not len(key):
                    raise ValueError("zero-length key")
                if value is not None and not len(value):
                    raise ValueError("zero-length value")
                current_kv[key] = value
        except ValueError as e:
            print(f"failed to parse input as key[=value] pairs: {e}", file=sys.stderr)
            exit(1)
        setattr(namespace, self.dest, current_kv)


# Convenience wrapper for executing external binaries
def command(name):
    binary = shutil.which(name)
    if not binary:
        raise Exception(f"{name} not found in PATH or not executable")

    def inner(
        *a,
        stdin=None,
        capture_stdout=False,
        capture_stderr=False,
        silent=False,
        fatal=True,
    ):
        args = [
            binary,
            *[e for e in a if e is not None],
        ]  # Filter None-elements from arguments
        if not silent:
            print("==>", " ".join(args))
        result = subprocess.run(
            args,
            input=stdin,
            stdout=subprocess.PIPE if capture_stdout else None,
            stderr=subprocess.PIPE if capture_stderr else None,
            text=True,
        )
        if result.returncode != 0 and fatal:
            exit(result.returncode)
        return result

    return inner


# Define external commands used by this script
talosctl = command("talosctl")
helm = command("helm")
flux = command("flux")
kubectl = command("kubectl")


# Utility for waiting for a port to become open
def wait_socket(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        while s.connect_ex((host, port)):
            time.sleep(1)


# Utility for checking the existence of Kubernetes resources
def check_resource(name, namespace=None):
    args = [
        "get",
        "-oname",
        name,
    ]
    if namespace:
        args += ["--namespace", namespace]

    result = kubectl(
        *args, capture_stdout=True, capture_stderr=True, silent=True, fatal=False
    )
    return result.returncode == 0


def resolve_gateway_api_version():
    """Resolve the Gateway API CRD version compatible with the Cilium Helm chart."""
    # Get Cilium version from Helm
    result = helm(
        "search",
        "repo",
        "cilium/cilium",
        "-o",
        "json",
        capture_stdout=True,
        silent=True,
    )
    cilium_version = json.loads(result.stdout)[0]["version"]

    # Fetch go.mod from Cilium repo
    go_mod_url = (
        f"https://raw.githubusercontent.com/cilium/cilium/v{cilium_version}/go.mod"
    )
    go_mod = requests.get(go_mod_url).text

    # Parse gateway-api version
    gw_version = re.search(r"sigs\.k8s\.io/gateway-api\s+(v[\d.]+)", go_mod).group(1)
    # Extract major.minor (handle pseudo-versions like v1.3.1-0.20250611...)
    major_minor = re.match(r"(v\d+\.\d+)", gw_version).group(1)

    # Query Gateway API releases to find latest matching minor
    releases_url = "https://api.github.com/repos/kubernetes-sigs/gateway-api/releases"
    releases = requests.get(releases_url).json()

    try:
        return next(
            rel["tag_name"]
            for rel in releases
            if rel["tag_name"].startswith(major_minor) and "rc" not in rel["tag_name"]
        )
    except StopIteration:
        raise Exception(f"Could not find Gateway API release for {major_minor}")


def main():
    # Parse shell arguments
    parser = argparse.ArgumentParser(
        description="Bootstrap and configure a provisioned Talos Linux cluster."
    )
    parser.add_argument(
        "config", metavar="<config-file>", help="configuration of the cluster"
    )
    parser.add_argument(
        "-b",
        "--bootstrap",
        nargs="?",
        metavar="node[=ip],...",
        action=KeyValueAction,
        help="bootstrap the given nodes, optionally using alternative IPs (or hostnames)",
    )
    parser.add_argument(
        "-s",
        "--skip-cluster-configuration",
        action="store_true",
        help="bootstrap/configure Talos only, skip K8s cluster configuration",
    )
    args = parser.parse_args()

    # Get absolute path of config before changing directory
    config_path = os.path.abspath(args.config)
    config_dir = os.path.dirname(config_path)

    # Change to config directory so relative paths work
    os.chdir(config_dir)

    # Load the bootstrap configuration
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)

    # Validate the bootstrap configuration
    try:
        config_schema.validate(config)
    except SchemaError as se:
        raise se

    # Initialize empty variables for easier processing
    config["cluster"]["domain"] = config["cluster"].get("domain", "")
    config["cluster"]["cilium"] = config["cluster"].get("cilium", {})
    config["worker"]["nodes"] = config["worker"]["nodes"] or {}
    args.bootstrap = args.bootstrap or {}

    # Validate given arguments
    all_nodes = (
        config["controlplane"]["nodes"].keys() | config["worker"]["nodes"].keys()
    )
    for n in args.bootstrap.keys():
        if n not in all_nodes:
            print(f"unknown node: {n}", file=sys.stderr)
            exit(1)

    # Append the domain to the given URI parts
    def fqdn(*parts):
        return ".".join(filter(None, [*parts, config["cluster"]["domain"]]))

    # Utility for waiting for a node to reach a given stage
    def wait_stage(node, stage, insecure=False):
        print(f'Waiting for {node} to reach stage "{stage}"...')
        while True:
            result = talosctl(
                "get",
                "machinestatus",
                "--nodes",
                args.bootstrap[node] if args.bootstrap.get(node) else fqdn(node),
                "--insecure" if insecure else None,
                "-oyaml",
                capture_stdout=True,
                capture_stderr=True,
                silent=True,
                fatal=False,
            )
            if result.returncode == 0:
                output = yaml.safe_load(result.stdout)
                if output["spec"]["stage"] == stage:
                    break
            time.sleep(1)

    # Apply a configuration file to a set of nodes including the given global patches
    def apply_configuration(node_set, configuration_file, global_patches):
        for node, node_patches in node_set.items():
            talosctl(
                "apply-config",
                "--nodes",
                args.bootstrap[node] if args.bootstrap.get(node) else fqdn(node),
                "--file",
                configuration_file,
                *[
                    # Force a reboot, automatic detection is a bit flaky with --insecure
                    f if node in args.bootstrap else None
                    for f in ["--insecure", "--mode", "reboot"]
                ],
                *[
                    e
                    for p in [*global_patches, *(node_patches or [])]
                    for e in ("--config-patch", p)
                ],
            )

    # Parse the custom installation image if specified
    if image := config["cluster"].get("image"):
        if ":" not in image:
            version = talosctl(
                "version", "--client", "--short", capture_stdout=True
            ).stdout.split()[-1]
            image = f"{image}:{version}"

    # Generate cluster configuration
    talosctl(
        "gen",
        "config",
        config["cluster"]["name"],
        f"https://{fqdn(config['controlplane']['record'])}:6443",
        "--force",
        *["--install-image", image] if image else [],
        "--with-secrets",
        config["cluster"]["secrets"],
        *[e for p in config["cluster"]["patches"] for e in ("--config-patch", p)],
    )

    # Wait for control plane nodes if bootstrapping the cluster
    for node in config["controlplane"]["nodes"].keys():
        if node in args.bootstrap:
            wait_stage(node, "maintenance", insecure=True)
        else:
            wait_stage(node, "running")

    # Apply cluster configuration to control plane nodes
    apply_configuration(
        config["controlplane"]["nodes"],
        "controlplane.yaml",
        config["controlplane"].get("patches", []),
    )

    # Wait for worker nodes
    for node in config["worker"]["nodes"].keys():
        if node in args.bootstrap:
            wait_stage(node, "maintenance", insecure=True)
        else:
            wait_stage(node, "running")

    # Apply cluster configuration to worker nodes
    apply_configuration(
        config["worker"]["nodes"],
        "worker.yaml",
        config["worker"].get("patches", []),
    )

    # Form a list of the FQDNs/endpoints for control plane and worker nodes
    control_plane_nodes = [fqdn(n) for n in config["controlplane"]["nodes"].keys()]
    worker_nodes = [fqdn(n) for n in config["worker"]["nodes"].keys()]

    # Use all control plane nodes as endpoints by default
    endpoints = control_plane_nodes
    if config["controlplane"].get("record-as-endpoint"):
        # Switch to using the record instead if requested (e.g., for remote cluster)
        endpoints = [fqdn(config["controlplane"]["record"])]

    # Generate and update talosconfig
    talosctl("--talosconfig", "talosconfig", "config", "endpoint", *endpoints)
    talosctl("--talosconfig", "talosconfig", "config", "node", control_plane_nodes[0])
    talosctl("config", "merge", "talosconfig")

    # Ensure proper talosconfig permissions
    os.chmod(os.path.expanduser("~/.talos/config"), 0o600)

    # Bootstrap the cluster if all nodes are marked to be bootstrapped
    if args.bootstrap.keys() == all_nodes:
        # There is supposedly a separate "installing" stage, so this should wait until installation
        # has finished, but this hasn't been verified yet (installation goes too fast if the node
        # already has the images, which is the case during repeated testing)
        wait_stage(control_plane_nodes[0], "booting")

        # Bootstrapping may fail with, e.g., "FailedPrecondition desc = time is not in sync yet"
        # while the nodes are still booting, so just try it repeatedly until it succeeds
        silent = False
        while True:
            result = talosctl(
                "bootstrap",
                "--nodes",
                control_plane_nodes[0],
                capture_stderr=True,
                silent=silent,
                fatal=False,
            )
            if result.returncode == 0:
                break
            silent = True

    if len(args.bootstrap):
        to_reboot = [fqdn(node) for node in args.bootstrap.keys()]
        for node in set(to_reboot) & set(control_plane_nodes):
            wait_stage(
                node, "running"
            )  # Wait for the control plane nodes to start running

        for node in set(to_reboot) & set(worker_nodes):
            wait_stage(
                node, "running"
            )  # Then, wait for the worker nodes to start running

        # Reboot newly bootstrapped nodes, since they won't apply some
        # configuration (such as certificates) directly for some reason
        # TODO: Open an issue about this
        talosctl(
            "reboot",
            "--nodes",
            ",".join(to_reboot),
            "--wait=false",  # We can't wait here, the cluster won't become ready without CNI
        )

        # Wait a few seconds for the nodes to switch into rebooting stage
        time.sleep(5)

        for node in to_reboot:
            wait_stage(node, "running")  # Then, wait for the nodes to complete reboot

    # Stop here if we're only bootstrapping/configuring Talos
    if args.skip_cluster_configuration:
        exit(0)

    # Kubernetes API operations are available after this
    print("Waiting for the control plane to respond...")
    # If applying configuration caused a reboot, wait for the node(s) to go down first
    time.sleep(5)
    wait_socket(fqdn(config["controlplane"]["record"]), 6443)

    # Generate and update kubeconfig, always overwrite to prevent stale contexts from accumulating
    talosctl("kubeconfig", stdin="o\n")

    # Ensure proper kubeconfig permissions
    os.chmod(os.path.expanduser(os.getenv("KUBECONFIG", "~/.kube/config")), 0o600)

    # Excluded resource types that cause trouble
    excluded_types = {
        "componentstatuses",
        "validatingadmissionpolicies.admissionregistration.k8s.io",
        "validatingadmissionpolicybindings.admissionregistration.k8s.io",
        "nodes.metrics.k8s.io",
        "pods.metrics.k8s.io",
    }

    # Discover non-namespaced and namespaced resource types from the API server
    resource_types = []
    for i in range(2):
        result = kubectl(
            "api-resources",
            "--verbs=list",
            "-o=name",
            f"--namespaced={'true' if i else 'false'}",
            capture_stdout=True,
        )
        resource_types.append(
            ",".join(
                (
                    resource_type
                    for resource_type in result.stdout.strip().split("\n")
                    if resource_type not in excluded_types
                )
            )
        )

    print("Cleaning up Flannel resources...")
    for i in range(2):
        kubectl(
            "--namespace=kube-system" if i else None,
            "delete",
            "--ignore-not-found",
            "--selector=k8s-app=flannel",
            resource_types[i],
        )

    print("Cleaning up kube-proxy resources...")
    for i in range(2):
        kubectl(
            "--namespace=kube-system" if i else None,
            "delete",
            "--ignore-not-found",
            resource_types[i],
            "kube-proxy",
        )

    # Options for bootstrapping Cilium
    cilium_opts = [
        "ipam.mode=kubernetes",
        "kubeProxyReplacement=true",
        "bpf.masquerade=true",  # eBPF-based masquerading
        "securityContext.capabilities.ciliumAgent={CHOWN,KILL,NET_ADMIN,NET_RAW,IPC_LOCK,"
        "SYS_ADMIN,SYS_RESOURCE,DAC_OVERRIDE,FOWNER,SETGID,SETUID}",
        "securityContext.capabilities.cleanCiliumState={NET_ADMIN,SYS_ADMIN,SYS_RESOURCE}",
        "cgroup.autoMount.enabled=false",
        "cgroup.hostRoot=/sys/fs/cgroup",
        # Handled by KubePrism
        # (https://www.talos.dev/latest/kubernetes-guides/configuration/kubeprism/)
        "k8sServiceHost=localhost",
        "k8sServicePort=7445",
        # Enable automatic rollout of configuration updates
        "rollOutCiliumPods=true",
        "envoy.rollOutPods=true",
        "hubble.relay.rollOutPods=true",
        "hubble.ui.rollOutPods=true",
        "operator.rollOutPods=true",
    ]

    # Cilium deploys its operator with 2 replicas by default, which may impede it becoming ready in
    # certain cluster configurations. Do a best-effort guess whether we should limit the replicas to
    # one: either there is just one worker node, or if there are no worker nodes the user likely has
    # removed the control plane node taint, at which point there might still be just one node total.
    if len(worker_nodes) == 1 or (
        len(worker_nodes) == 0 and len(control_plane_nodes) == 1
    ):
        cilium_opts += ["operator.replicas=1"]

    if config["cluster"]["cilium"].get("metrics"):
        cilium_opts += [
            "prometheus.enabled=true",  # cilium-agent metrics
            "operator.prometheus.enabled=true",  # cilium-operator metrics
        ]

    if hubble := config["cluster"]["cilium"].get("hubble"):
        enabled = "true" if hubble["enabled"] else "false"
        cilium_opts += [
            f"hubble.enabled={enabled}",  # Enable Hubble (CLI)
            f"hubble.ui.enabled={enabled}",  # Enable Hubble UI
            f"hubble.relay.enabled={enabled}",  # Enable Hubble Relay
        ]
        if hubble["enabled"] and hubble.get("metrics"):
            # Hubble metrics
            cilium_opts += [
                "hubble.metrics.enableOpenMetrics=true",
                "hubble.metrics.enabled={dns,drop,tcp,flow,port-distribution,icmp,"
                "httpV2:exemplars=true;labelsContext=source_ip\\,source_namespace\\,"
                "source_workload\\,destination_ip\\,destination_namespace\\,"
                "destination_workload\\,traffic_direction}",
            ]

    enable_hardening = True
    enable_audit_mode = True
    if hardening := config["cluster"]["cilium"].get("hardening"):
        enable_hardening = hardening["enabled"]
        enable_audit_mode = hardening["audit-mode"]

    if enable_hardening:
        cilium_opts += [
            "policyEnforcementMode=always",  # Enforce network policies
            "hostFirewall.enabled=true",  # Enable host policies (host-level network policies)
            "extraConfig.allow-localhost=policy",  # Enforce policies for node-local traffic as well
        ]

    if enable_audit_mode:
        cilium_opts += [
            "policyAuditMode=true",  # Audit mode, do not block traffic
        ]

    if native_routing := config["cluster"]["cilium"].get("native-routing"):
        if native_routing["enabled"]:
            cilium_opts += [
                "routingMode=native",  # Enable native routing
                f"ipv4NativeRoutingCIDR={native_routing['ipv4-cidr']}",
                f"autoDirectNodeRoutes={'true' if native_routing['direct-routes'] else 'false'}",
            ]

    if config["cluster"]["cilium"].get("netkit"):
        cilium_opts += [
            "bpf.datapathMode=netkit",  # netkit device mode, REQUIRES kernel >= 6.8 (Talos v1.9)
        ]

    if bgp := config["cluster"]["cilium"].get("bgp"):
        if bgp["enabled"]:
            cilium_opts += [
                "bgpControlPlane.enabled=true",  # Enable BGP Control Plane
            ]

    if node_ipam := config["cluster"]["cilium"].get("node-ipam"):
        if node_ipam["enabled"]:
            cilium_opts += [
                "nodeIPAM.enabled=true",  # Use node IPs for LoadBalancer services
            ]

    # Normally Envoy has SYS_ADMIN, but that can be replaced with PERFMON and BPF, see
    # https://github.com/cilium/cilium/blob/v1.16.1/install/kubernetes/cilium/values.yaml#L2263-L2271
    envoy_caps = ["NET_ADMIN", "PERFMON", "BPF"]
    if gw_api := config["cluster"]["cilium"].get("gateway-api"):
        if gw_api["enabled"]:
            cilium_opts += [
                "gatewayAPI.enabled=true",  # Enable Gateway API support
                "gatewayAPI.enableAlpn=true",  # GRPCRoutes with TLS require ALPN for HTTP/2
                "gatewayAPI.enableAppProtocol=true",  # GEP-1911: Backend Protocol Selection
            ]
            if gw_api.get("host-network"):
                cilium_opts += ["gatewayAPI.hostNetwork.enabled=true"]
            if gw_api.get("privileged-ports"):
                # https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/gateway-api/#bind-to-privileged-port
                cilium_opts += [
                    "envoy.securityContext.capabilities.keepCapNetBindService=true"
                ]
                envoy_caps += ["NET_BIND_SERVICE"]

    cilium_opts += [
        f"envoy.securityContext.capabilities.envoy={{{','.join(envoy_caps)}}}"
    ]

    # Add Helm repo for Cilium
    helm("repo", "add", "cilium", "https://helm.cilium.io/")

    # Install Gateway API CRDs if gateway-api is enabled
    if config["cluster"]["cilium"].get("gateway-api", {}).get("enabled"):
        gw_api_version = resolve_gateway_api_version()
        print(f"Installing Gateway API CRDs {gw_api_version}...")
        # Use experimental-install to include TLSRoute CRD.
        # Cilium has bug where if TLSRoute CRD is missing `enqueueRequestForBackendService` fails
        # and it registers no reconciliation actions for HTTPRoutes due to code not handling
        # missing CRD schema.
        # https://github.com/cilium/cilium/blob/v1.18.6/operator/pkg/gateway-api/gateway.go#L270-L275
        # This was partially fixed in https://github.com/cilium/cilium/pull/38874 but not fully.
        # TODO: Send an upstream Cilium patch.
        kubectl(
            "apply",
            "--server-side",
            "-f",
            "https://github.com/kubernetes-sigs/gateway-api/releases/download/"
            f"{gw_api_version}/experimental-install.yaml",
        )

    # Install Cilium using Helm
    helm(
        "upgrade",
        "--install",
        "cilium",
        "cilium/cilium",
        "--namespace",
        "kube-system",
        "--wait",
        *[e for o in cilium_opts for e in ("--set", o)],
    )

    # Cilium operator installs CRDs during runtime. Wait for the CRDs to be installed so that
    # manifests can use them.
    if config["cluster"]["cilium"].get("gateway-api", {}).get("enabled"):
        print("Waiting for Cilium Gateway API CRDs...")
        while not check_resource("crd/ciliumgatewayclassconfigs.cilium.io"):
            time.sleep(1)

    # Add Mozilla SOPS key
    if "sops" in config["cluster"] and not check_resource(
        "secret/sops-gpg", namespace="flux-system"
    ):
        # Fetch secret key from GPG
        key_data = gnupg.GPG().export_keys(
            config["cluster"]["sops"], secret=True, expect_passphrase=False
        )

        # Inject it into the cluster
        # NOTE: kubectl is not idempotent: https://github.com/kubernetes/kubectl/issues/1421
        if not check_resource("namespace/flux-system"):
            kubectl("create", "namespace", "flux-system")

        kubectl(
            "create",
            "secret",
            "generic",
            "sops-gpg",
            "--namespace=flux-system",
            "--from-file=sops.asc=/dev/stdin",
            stdin=key_data,
        )

    if "flux" in config["cluster"]:
        flux_opts = []
        if "ssh" in config["cluster"]["flux"]:
            # SSH configuration given, bootstrap flux
            flux_opts += [
                "bootstrap",
                "git",
                f"--url={config['cluster']['flux']['url']}",
                f"--branch={config['cluster']['flux']['branch']}",
                f"--path=clusters/{config['cluster']['name']}",
                f"--private-key-file={config['cluster']['flux']['key']}",
            ]
        else:
            # No SSH configuration given, just perform a Flux install
            flux_opts += ["install"]

        # Check for installation of specific components only
        if "components" in config["cluster"]["flux"]:
            flux_opts += [f"--components={config['cluster']['flux']['components']}"]
        if "components-extra" in config["cluster"]["flux"]:
            flux_opts += [
                f"--components-extra={config['cluster']['flux']['components-extra']}"
            ]

        # Check if Flux should watch all namespaces for resources
        all_namespaces = (
            "all-namespaces" not in config["cluster"]["flux"]
            or config["cluster"]["flux"]["all-namespaces"]
        )
        flux_opts += [f"--watch-all-namespaces={'true' if all_namespaces else 'false'}"]

        # Perform bootstrap/installation
        flux(*flux_opts)

    # Apply additional manifests as a Kustomization
    if manifest_dir := config["cluster"].get("manifests"):
        manifests, crds = [], []
        for manifest in yaml.safe_load_all(
            kubectl(
                "kustomize", "--enable-helm", manifest_dir, capture_stdout=True
            ).stdout
        ):
            if (
                manifest.get("apiVersion") == "apiextensions.k8s.io/v1"
                and manifest.get("kind") == "CustomResourceDefinition"
            ):
                crds.append(manifest)
            else:
                manifests.append(manifest)

        # Apply CRDs before everything else
        if len(crds):
            kubectl("apply", "-f", "-", stdin=yaml.safe_dump_all(crds))
        if len(manifests):
            kubectl("apply", "-f", "-", stdin=yaml.safe_dump_all(manifests))

    # Gateway API flakiness: restart the Cilium operator and agents to pick up existing gateways,
    # see https://docs.cilium.io/en/latest/network/servicemesh/gateway-api/gateway-api/#installation
    if config["cluster"]["cilium"].get("gateway-api", {}).get("enabled"):
        kubectl(
            "--namespace",
            "kube-system",
            "rollout",
            "restart",
            "deployment/cilium-operator",
            "daemonset/cilium",
        )

    # Wait for the cluster to be healthy
    talosctl("health")


if __name__ == "__main__":
    main()
