#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# bootstrap.py - Bootstrap a provisioned Talos Linux cluster.
# (c) Dennis Marttinen, Veeti Poutsalo 2022

import argparse
import os
import shutil
import socket
import subprocess
import time
import sys

import gnupg
import yaml
from schema import And, Optional, Or, Schema, SchemaError

str_schema = And(str, And(len, error="empty strings not allowed"))
file_schema = And(
    str_schema, And(lambda x: os.path.isfile(x), error="file not found: {}")
)
dir_schema = And(
    str_schema, And(lambda x: os.path.isdir(x), error="directory not found: {}")
)
patch_schema = And(
    [str], And(lambda x: len(x) == len(set(x)), error="duplicates not allowed: {}")
)

# Schema for the bootstrap configuration files
config_schema = Schema(
    {
        "cluster": {
            "name": str_schema,
            "domain": str_schema,
            "secrets": file_schema,
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
            Optional("patches"): patch_schema,
            Optional("manifests"): dir_schema,
        },
        "controlplane": {
            "record": str_schema,
            Optional("patches"): patch_schema,
            "nodes": {str_schema: Or(patch_schema, None)},
        },
        "worker": {
            Optional("patches"): patch_schema,
            "nodes": Or({str_schema: Or(patch_schema, None)}, None),
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

    def inner(*a, stdin=None, capture_output=False, silent=False, fatal=True):
        args = [
            binary,
            *[e for e in a if e is not None],
        ]  # Filter None-elements from arguments
        if not silent:
            print("==>", " ".join(args))
        result = subprocess.run(
            args, input=stdin, capture_output=capture_output, text=True
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


# Utility for waiting for a node to reach a given stage
def wait_stage(node, stage):
    print(f'"Waiting for {node} to reach stage "{stage}"..."')
    while True:
        result = talosctl(
            "get",
            "machinestatus",
            "--nodes",
            node,
            "-oyaml",
            capture_output=True,
            silent=True,
            fatal=False,
        )
        if result.returncode == 0:
            output = yaml.safe_load(result.stdout)
            if output["spec"]["stage"] == stage:
                break
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

    result = kubectl(*args, capture_output=True, silent=True, fatal=False)
    return result.returncode == 0


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

    # Load the bootstrap configuration
    with open(args.config, "r") as file:
        config = yaml.safe_load(file)

    # Validate the bootstrap configuration
    try:
        config_schema.validate(config)
    except SchemaError as se:
        raise se

    # Initialize empty dicts for easier processing
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
        return ".".join([*parts, config["cluster"]["domain"]])

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

    # Generate cluster configuration
    talosctl(
        "gen",
        "config",
        config["cluster"]["name"],
        f"https://{fqdn(config['controlplane']['record'])}:6443",
        "--force",
        "--with-secrets",
        config["cluster"]["secrets"],
        *[e for p in config["cluster"]["patches"] for e in ("--config-patch", p)],
    )

    # Apply cluster configuration to control plane nodes
    apply_configuration(
        config["controlplane"]["nodes"],
        "controlplane.yaml",
        config["controlplane"].get("patches", []),
    )

    # Apply cluster configuration to worker nodes
    apply_configuration(
        config["worker"]["nodes"],
        "worker.yaml",
        config["worker"].get("patches", []),
    )

    # Form a list of the FQDNs/endpoints for control plane and worker nodes
    controlplane_endpoints = [fqdn(n) for n in config["controlplane"]["nodes"].keys()]
    worker_endpoints = [fqdn(n) for n in config["worker"]["nodes"].keys()]

    # Generate and update talosconfig and kubeconfig
    talosctl(
        "--talosconfig", "talosconfig", "config", "endpoint", *controlplane_endpoints
    )
    talosctl(
        "--talosconfig", "talosconfig", "config", "node", controlplane_endpoints[0]
    )
    talosctl("config", "merge", "talosconfig")
    talosctl("kubeconfig", stdin="r\n")  # Always rename existing configs

    # Ensure proper config permissions
    for path in ["~/.kube/config", "~/.talos/config"]:
        os.chmod(os.path.expanduser(path), 0o600)

    # Bootstrap the cluster if all nodes are marked to be bootstrapped
    if args.bootstrap.keys() == all_nodes:
        # There is supposedly a separate "installing" stage, so this should wait until installation
        # has finished, but this hasn't been verified yet (installation goes too fast if the node
        # already has the images, which is the case during repeated testing)
        wait_stage(controlplane_endpoints[0], "booting")
        talosctl("bootstrap", "--nodes", controlplane_endpoints[0])

    if len(args.bootstrap):
        to_reboot = [fqdn(node) for node in args.bootstrap.keys()]
        for node in set(to_reboot) & set(controlplane_endpoints):
            wait_stage(
                node, "running"
            )  # Wait for the control plane nodes to start running

        for node in set(to_reboot) & set(worker_endpoints):
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

    # Stop here if we're only bootstrapping/configuring Talos
    if args.skip_cluster_configuration:
        exit(0)

    # Kubernetes API operations are available after this
    print("Waiting for the control plane to respond...")
    wait_socket(fqdn(config["controlplane"]["record"]), 6443)

    # Options for bootstrapping Cilium
    cilium_opts = [
        "ipam.mode=kubernetes",
        "kubeProxyReplacement=true",
        "securityContext.capabilities.ciliumAgent={CHOWN,KILL,NET_ADMIN,NET_RAW,IPC_LOCK,"
        "SYS_ADMIN,SYS_RESOURCE,DAC_OVERRIDE,FOWNER,SETGID,SETUID}",
        "securityContext.capabilities.cleanCiliumState={NET_ADMIN,SYS_ADMIN,SYS_RESOURCE}",
        "cgroup.autoMount.enabled=false",
        "cgroup.hostRoot=/sys/fs/cgroup",
        # Handled by KubePrism
        # (https://www.talos.dev/latest/kubernetes-guides/configuration/kubeprism/)
        "k8sServiceHost=localhost",
        "k8sServicePort=7445",
        "prometheus.enabled=true",  # cilium-agent metrics
        "operator.prometheus.enabled=true",  # cilium-operator metrics
        # Enable Hubble and all the metrics
        "hubble.enabled=true",
        "hubble.ui.enabled=true",
        "hubble.relay.enabled=true",
        "hubble.metrics.enableOpenMetrics=true",
        "hubble.metrics.enabled={dns,drop,tcp,flow,port-distribution,icmp,"
        "httpV2:exemplars=true;labelsContext=source_ip\,source_namespace\,"  # noqa: W605
        "source_workload\,destination_ip\,destination_namespace\,"  # noqa: W605
        "destination_workload\,traffic_direction}",  # noqa: W605
        # Network hardening
        "policyEnforcementMode=always",  # Enforce network policies
        "policyAuditMode=true",  # Audit mode, do not block traffic (DISABLE WHEN CONFIGURED!)
        "hostFirewall.enabled=true",  # Enable host policies (host-level network policies)
        "extraConfig.allow-localhost=policy",  # Enforce policies for node-local traffic as well
    ]

    # Add Helm repo for Cilium
    helm("repo", "add", "cilium", "https://helm.cilium.io/")

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

    # Wait for the cluster to be healthy
    talosctl("health")

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
        check_resource("namespace/flux-system") or kubectl(
            "create", "namespace", "flux-system"
        )
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
    if "manifests" in config["cluster"]:
        kubectl("apply", "-k", config["cluster"]["manifests"])


if __name__ == "__main__":
    main()
