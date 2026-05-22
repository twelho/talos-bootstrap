# Talos Bootstrap

Talos Bootstrap is an automated bootstrapping and configuration tool for deploying [Talos Linux](https://www.talos.dev/) clusters once they have been provisioned. The repository is structured as follows:

- [`clusters`](clusters) contains the bootstrap configuration for various clusters, each in their own file. Create a new file here to configure a new cluster. Take a look at [`clusters/example.yaml`](clusters/example.yaml) for the configuration schema.
- [`patch`](patch) contains the various strategic merge patches that are applied to the machine configurations of nodes as instrumented by the configurations in `clusters`. Take a look at [`example.yaml`](patch/example.yaml) for detailed information about the patch format.

> [!IMPORTANT]
> The bootstrap configuration file schema is intentionally unstable. Upon updating `talos-bootstrap`, one might need to update existing cluster configuration files to match the new schema. However, the strict validation logic should help with pointing out issues, such as changed fields. When updating cluster configuration, please refer to [`clusters/example.yaml`](clusters/example.yaml), which will always comply with the current schema and describe the fields.

## Installation

```shell
go install github.com/twelho/talos-bootstrap/cmd/bootstrap@latest
```

Or build from a checkout:

```shell
make build
```

This produces the `bootstrap` binary. Check the available subcommands and flags with `bootstrap --help`.

## Using `talos-bootstrap`

`talos-bootstrap` automates the end-to-end setup of a Talos Linux cluster. It only requires a set of un-configured Talos Linux nodes in a network with the proper DNS configuration. After choosing a cluster configuration from one of the files in [`clusters`](clusters) and ensuring that the [secrets](#secrets) are present, bootstrapping the cluster is as easy as running

```shell
bootstrap bootstrap clusters/<cluster>.yaml
```

and monitoring the progress. The tool talks to Talos, Kubernetes, Helm and Flux through their respective Go SDKs, so the only external binary it shells out to for the bootstrap flow is `gpg` (for exporting a SOPS GPG key from the local keyring).

It first generates Talos machine configurations and patches the nodes, then applies the [Cilium](https://cilium.io/) CNI networking layer via the Helm SDK, optionally installs the [Gateway API](https://gateway-api.sigs.k8s.io/) CRDs that match the deployed Cilium version, optionally installs the [Flux](https://fluxcd.io/) controllers, and finally applies any static manifests in the form of a [Kustomization](https://kustomize.io/). Flux GitRepository, OCIRepository, Kustomization, and related sync objects should be supplied through the post-bootstrap manifests path.

### Rendering the Cilium configuration

`talos-bootstrap` is the source of truth for the Cilium installation. To render the same configuration as a standalone Helm `values.yaml` for external consumers, use:

```shell
bootstrap cilium values clusters/<cluster>.yaml
```

### Exporting cluster facts for downstream consumers

Downstream GitOps repos that template against the same cluster (cluster name, API endpoint, native-routing CIDR, feature toggles) can read a stable JSON document instead of re-encoding those values by hand:

```shell
bootstrap facts clusters/<cluster>.yaml
```

The document is versioned via `schemaVersion`. Secrets paths, GPG fingerprints, and other local-filesystem or sensitive fields are intentionally omitted, so the output is safe to commit and publish.

## Secrets

The bootstrapping process requires a `secrets.yaml` which contains the secrets for `talosctl` and the cluster. The expected location of this file is defined by the cluster configuration in `clusters`. Additionally, for SOPS, one can optionally provide a GPG ID/fingerprint or an age key file that can be imported into the cluster.

If you want to create new secrets for a cluster, do the following:

1. Create a new directory under `secrets` named after your cluster.
2. Enter that directory and run `talosctl gen secrets` to get a new `secrets.yaml`.
3. Ensure that your cluster configuration under `clusters` uses the newly generated `secrets.yaml`.
4. Create a SOPS GPG key:
   ```
   gpg --batch --full-gen-key << EOF
   %no-protection
   Key-Type: EdDSA
   Key-Curve: Ed25519
   Key-Usage: sign
   Subkey-Type: ECC
   Subkey-Curve: Curve25519
   Subkey-Usage: encrypt
   Expire-Date: 0
   Name-Comment: Flux SOPS Key
   Name-Real: my-cluster.example.com
   EOF
   ```
5. Proceed with the [bootstrapping process](#using-bootstrap).

## Authors

- Dennis Marttinen ([@twelho](https://github.com/twelho))
- Veeti Poutsalo ([@Polychoronix](https://github.com/Polychoronix))

## License

[MIT](https://opensource.org/licenses/MIT) ([LICENSE](LICENSE))
