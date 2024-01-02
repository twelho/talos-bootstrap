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

import yaml
from schema import And, Optional, Or, Schema, SchemaError

# Timeout for individual bootstrap operations
timeout = "20m"
# Time to wait for configuration to apply
delay = 15

str_schema = And(str, And(len, error="empty strings not allowed"))
path_schema = And(
    str_schema, And(lambda x: os.path.isfile(x), error="file not found: {}")
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
            "secrets": path_schema,
            Optional("sops"): path_schema,
            "flux": {"url": str_schema, "branch": str_schema, "key": path_schema},
            Optional("patches"): patch_schema,
        },
        "controlplane": {
            "record": str_schema,
            Optional("patches"): patch_schema,
            "nodes": {str_schema: Or(patch_schema, None)},
        },
        "worker": {
            Optional("patches"): patch_schema,
            "nodes": {str_schema: Or(patch_schema, None)},
        },
    }
)

# Parse shell arguments
parser = argparse.ArgumentParser(
    description="Bootstrap a provisioned Talos Linux cluster."
)
parser.add_argument(
    "config", metavar="<config-file>", help="bootstrap configuration of the cluster"
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


def with_domain(*parts):
    return ".".join([*parts, config["cluster"]["domain"]])


def command(name):
    binary = shutil.which(name)
    if not binary:
        raise Exception(f"{name} not found in PATH or not executable")
    return lambda *a: [
        print("==>", " ".join([binary, *a])),
        subprocess.run([binary, *a]),
    ]


# Define external commands used by this script
talosctl = command("talosctl")
helm = command("helm")
flux = command("flux")
kubectl = command("kubectl")


# Routine that waits for the API server port to be available
def wait_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        while s.connect_ex((config["controlplane"]["record"], 6443)):
            time.sleep(1)


# Generate cluster configuration
talosctl(
    "gen",
    "config",
    config["cluster"]["name"],
    f"https://{config['controlplane']['record']}.{config['cluster']['domain']}:6443",
    "--with-cluster-discovery=false",
    "--with-secrets",
    config["cluster"]["secrets"],
    *[e for p in config["cluster"]["patches"] for e in ("--config-patch", p)],
)

# Form the FQDNs for control plane and worker nodes
controlplane_nodes = [with_domain(n) for n in config["controlplane"]["nodes"].keys()]

# Apply cluster configuration to control plane nodes
controlplane_patches = config["controlplane"].get("patches", [])
for node, node_patches in config["controlplane"]["nodes"].items():
    talosctl(
        "apply-config",
        "--insecure",
        "--nodes",
        node,
        "--file",
        "controlplane.yaml",
        *[
            e
            for p in [*controlplane_patches, *(node_patches or [])]
            for e in ("--config-patch", p)
        ],
    )

# Apply cluster configuration to worker nodes
worker_patches = config["worker"].get("patches", [])
for node, node_patches in config["worker"]["nodes"].items():
    talosctl(
        "apply-config",
        "--insecure",
        "--nodes",
        node,
        "--file",
        "worker.yaml",
        *[
            e
            for p in [*worker_patches, *(node_patches or [])]
            for e in ("--config-patch", p)
        ],
    )

print(f"Waiting for { delay } seconds for the nodes to apply configuration...")
time.sleep(delay)

# Generate and update talosconfig and kubeconfig
talosctl("--talosconfig", "talosconfig", "config", "endpoint", *controlplane_nodes)
talosctl("--talosconfig", "talosconfig", "config", "node", controlplane_nodes[0])
talosctl("config", "merge", "talosconfig")
talosctl("kubeconfig")

# Ensure proper config permissions
for path in ["~/.kube/config", "~/.talos/config"]:
    os.chmod(os.path.expanduser(path), 0o600)

print(f"Waiting for { delay } seconds for the nodes to apply configuration...")
time.sleep(delay)

# Bootstrap the cluster
talosctl("bootstrap", "--nodes", controlplane_nodes[0])

print("Waiting for the control plane to respond...")
wait_socket()

# Options for bootstrapping Cilium
cilium_opts = [
    "ipam.mode=kubernetes",
    "kubeProxyReplacement=strict",
    f"k8sServiceHost={config['controlplane']['record']}.{config['cluster']['domain']}",
    "k8sServicePort=6443",
    "hubble.relay.enabled=true",
    "hubble.ui.enabled=true",
    "prometheus.enabled=true",
    "securityContext.privileged=true",
]

# Install Cilium using Helm
helm(
    "install",
    "cilium",
    "cilium/cilium",
    "--namespace",
    "kube-system",
    "--timeout",
    timeout,
    "--wait",
    *[e for o in cilium_opts for e in ("--set", o)],
)

# Wait for the cluster to be healthy
talosctl("health", "--wait-timeout", timeout)

# Add Mozilla Secret Operations key
if "sops" in config["cluster"]:
    kubectl("create", "namespace", "flux-system")
    kubectl(
        "create",
        "secret",
        "generic",
        "sops-gpg",
        "--namespace=flux-system",
        f"--from-file={config['cluster']['sops']}",
    )

# Bootstrap flux
flux(
    "bootstrap",
    "git",
    f"--url={config['cluster']['flux']['url']}",
    f"--branch={config['cluster']['flux']['branch']}",
    f"--path=clusters/{config['cluster']['name']}",
    f"--private-key-file={config['cluster']['flux']['key']}",
    "--silent",
)
