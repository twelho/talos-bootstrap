# Talos Bootstrap

Talos Bootstrap is an automated bootstrapping and configuration tool for deploying [Talos Linux](https://www.talos.dev/) clusters once they have been provisioned. The repository is structured as follows:

- [`clusters`](clusters) contains the bootstrap configuration for various clusters, each in their own file. Create a new file here to configure a new cluster. Take a look at [`example.yaml`](clusters/example.yaml) for the configuration schema.
- [`patch`](patch) contains the various strategic merge patches that are applied to the machine configurations of nodes as instrumented by the configurations in `clusters`. Take a look at [`example.yaml`](patch/example.yaml) for detailed information about the patch format.

## Dependencies

The [`bootstrap.py`](bootstrap.py) script depends on Python 3 and the `yaml` and `schema` Python packages.

- Install the dependencies with `pip3 install pyyaml schema`.

## Using the `bootstrap.py` script

The [`bootstrap.py`](bootstrap.py) script automates the end-to-end setup of a Talos Linux cluster. It only requires a set of un-configured Talos Linux nodes in a network with the proper DNS configuration. After choosing a cluster configuration from one of the available configurations in [`clusters`](clusters) and ensuring that the [secrets](#secrets) are present, bootstrapping the cluster is as easy as running

```shell
./bootstrap.py clusters/<cluster>.yaml
```

and monitoring the progress. The `bootstrap.py` script requires the `talosctl`, `helm` and `flux` binaries to be present in `$PATH`. First it will use `talosctl` to generate a configuration for the cluster and to patch the nodes, then it will apply the [Cilium](https://cilium.io/) CNI networking layer using `helm`, and finally it will use `flux` to install [Flux](https://fluxcd.io/) and point it to the upstream defined in the cluster configuration. If a SOPS GPG key is supplied in the cluster configuration, `kubectl` is used to create the SOPS secret in the `flux-system` namespace before installing Flux.

## Secrets

The bootstrapping process requires two files with secrets: a `secrets.yaml`, which contains the secrets for `talosctl` and the cluster, and a `flux.key`, which contains an SSH private key that Flux will use to access the configuration repository. The expected location of these files (in the `secrets` directory) is defined by the cluster configuration in `clusters`.

If you want to create new secrets for a cluster, do the following:

1. Create a new directory under `secrets` named after your cluster.
2. Enter that directory and run `talosctl gen secrets` to get a new `secrets.yaml`.
3. Run `ssh-keygen -t ed25519 -N "" -f flux.key` to create a new private and public key for Flux.
4. Ensure that your cluster configuration under `clusters` uses the newly generated `secrets.yaml` and `flux.key`.
5. Create a new repository to host your service layer deployments.
6. Add the public key in `flux.key.pub` to the `Repository settings > Access keys` (or similar) of that repository.
7. Proceed with the [bootstrapping process](#using-the-bootstrappy-script).

## Authors

- Dennis Marttinen ([@twelho](https://github.com/twelho))
- Veeti Poutsalo ([@VeetiPoutsalo](https://github.com/veetipoutsalo))

## License

[MIT](https://opensource.org/licenses/MIT) ([LICENSE](LICENSE))
