// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package talos

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cosi-project/runtime/pkg/resource"
	clusterapi "github.com/siderolabs/talos/pkg/machinery/api/cluster"
	machineapi "github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	clientconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	"github.com/siderolabs/talos/pkg/machinery/config/configpatcher"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
)

// Service exposes Talos node operations using a single in-memory talosconfig.
// Each operation builds its own short-lived gRPC client.
type Service struct {
	cfg *clientconfig.Config
}

// NewService loads the talosconfig at path. If path is empty, Talos' default
// path selection is used.
func NewService(path string) (*Service, error) {
	cfg, err := clientconfig.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open talosconfig: %w", err)
	}
	return &Service{cfg: cfg}, nil
}

// ApplyOpts configures a single ApplyConfig call.
type ApplyOpts struct {
	// Endpoint addresses an un-configured node directly when set; the value
	// is used both as the gRPC endpoint and as the node target.
	Endpoint string
	// Insecure switches the client to maintenance mode (no client cert,
	// server cert verification disabled). Use this for nodes that have not
	// yet had a configuration applied.
	Insecure bool
	// ForceReboot maps to ApplyConfigurationRequest_REBOOT. Otherwise the
	// node decides whether to reboot based on the diff.
	ForceReboot bool
	// Patches are applied on the client before submission (the Talos API
	// has no patch field of its own).
	Patches []string
}

// ApplyConfig sends a machine config to a node, optionally patched.
func (s *Service) ApplyConfig(ctx context.Context, node string, data []byte, o ApplyOpts) error {
	if len(o.Patches) > 0 {
		patches, err := configpatcher.LoadPatches(o.Patches)
		if err != nil {
			return fmt.Errorf("load node patches: %w", err)
		}
		out, err := configpatcher.Apply(configpatcher.WithBytes(data), patches)
		if err != nil {
			return fmt.Errorf("apply node patches: %w", err)
		}
		data, err = out.Bytes()
		if err != nil {
			return fmt.Errorf("marshal patched config: %w", err)
		}
	}

	cli, ctx, err := s.connect(ctx, node, o.Endpoint, o.Insecure)
	if err != nil {
		return err
	}
	defer cli.Close()

	mode := machineapi.ApplyConfigurationRequest_AUTO
	if o.ForceReboot {
		mode = machineapi.ApplyConfigurationRequest_REBOOT
	}
	_, err = cli.ApplyConfiguration(ctx, &machineapi.ApplyConfigurationRequest{
		Data: data,
		Mode: mode,
	})
	if err != nil {
		return fmt.Errorf("apply config to %s: %w", node, err)
	}
	return nil
}

// Bootstrap calls etcd bootstrap on a single control-plane node, retrying
// transient errors until success, a permanent failure, or context cancel.
// Bootstrap commonly fails with FailedPrecondition while the node is still
// booting (e.g. time not in sync), so transient retries are the correct
// behaviour here. AlreadyExists is treated as success: re-bootstrapping an
// already-initialised etcd is a no-op the user should not have to handle.
func (s *Service) Bootstrap(ctx context.Context, node string, retry time.Duration) error {
	cli, ctx, err := s.connect(ctx, node, "", false)
	if err != nil {
		return err
	}
	defer cli.Close()

	return retryUntil(ctx, "bootstrap etcd on "+node, retry, func() error {
		err := cli.Bootstrap(ctx, &machineapi.BootstrapRequest{})
		if alreadyExists(err) {
			return nil
		}
		return err
	})
}

// Reboot triggers a default-mode reboot on the listed nodes without waiting
// for them to come back up. The cluster CNI may not be installed yet at this
// point, in which case waiting would deadlock.
func (s *Service) Reboot(ctx context.Context, nodes []string) error {
	cli, ctx, err := s.connectMany(ctx, nodes, false)
	if err != nil {
		return err
	}
	defer cli.Close()

	if err := cli.Reboot(ctx); err != nil {
		return fmt.Errorf("reboot %v: %w", nodes, err)
	}
	return nil
}

// Kubeconfig retrieves the cluster admin kubeconfig from a control-plane node.
func (s *Service) Kubeconfig(ctx context.Context, node string) ([]byte, error) {
	cli, ctx, err := s.connect(ctx, node, "", false)
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	return cli.Kubeconfig(ctx)
}

// HealthRequest describes the cluster topology that the Talos health check
// needs to verify (which nodes are control planes, which are workers).
type HealthRequest struct {
	ControlPlanes []string
	Workers       []string
	WaitTimeout   time.Duration
}

// Health blocks until the cluster reports healthy or the context expires.
// Progress messages are emitted via the provided sink (or stderr if nil).
func (s *Service) Health(ctx context.Context, req HealthRequest, progress func(string)) error {
	cli, ctx, err := s.connect(ctx, "", "", false)
	if err != nil {
		return err
	}
	defer cli.Close()

	stream, err := cli.ClusterHealthCheck(ctx, req.WaitTimeout, &clusterapi.ClusterInfo{
		ControlPlaneNodes: req.ControlPlanes,
		WorkerNodes:       req.Workers,
	})
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("health check stream: %w", err)
		}
		if progress != nil {
			progress(msg.GetMessage())
		}
	}
}

// StageOpts configures a Stage / WaitStage call.
type StageOpts struct {
	Endpoint string
	Insecure bool
}

// Stage reads the current machine boot stage of a node.
func (s *Service) Stage(ctx context.Context, node string, o StageOpts) (runtime.MachineStage, error) {
	cli, ctx, err := s.connect(ctx, node, o.Endpoint, o.Insecure)
	if err != nil {
		return 0, err
	}
	defer cli.Close()

	res, err := cli.COSI.Get(ctx, resource.NewMetadata(
		runtime.NamespaceName, runtime.MachineStatusType, runtime.MachineStatusID, resource.VersionUndefined,
	))
	if err != nil {
		return 0, fmt.Errorf("read machinestatus: %w", err)
	}
	ms, ok := res.(*runtime.MachineStatus)
	if !ok {
		return 0, fmt.Errorf("unexpected resource type %T", res)
	}
	return ms.TypedSpec().Stage, nil
}

// WaitStage polls until the node reports the requested stage.
func (s *Service) WaitStage(ctx context.Context, node string, want runtime.MachineStage, o StageOpts) error {
	return retryUntil(ctx, "wait for stage "+want.String()+" on "+node, time.Second, func() error {
		got, err := s.Stage(ctx, node, o)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("stage %s, want %s", got, want)
		}
		return nil
	})
}

func (s *Service) connect(ctx context.Context, node, endpoint string, insecure bool) (*client.Client, context.Context, error) {
	if insecure {
		ep := endpoint
		if ep == "" {
			ep = node
		}
		c, err := newInsecureClient(ctx, ep)
		if err != nil {
			return nil, ctx, err
		}
		// In maintenance mode there is no apid to proxy by node name; the
		// gRPC connection is to the node itself.
		return c, ctx, nil
	}
	opts := []client.OptionFunc{client.WithConfig(s.cfg)}
	if endpoint != "" {
		opts = append(opts, client.WithEndpoints(endpoint))
	}
	c, err := client.New(ctx, opts...)
	if err != nil {
		return nil, ctx, fmt.Errorf("connect to talos api: %w", err)
	}
	if node != "" {
		ctx = client.WithNodes(ctx, node)
	}
	return c, ctx, nil
}

func (s *Service) connectMany(ctx context.Context, nodes []string, insecure bool) (*client.Client, context.Context, error) {
	if insecure {
		return nil, ctx, errors.New("insecure mode does not support multi-node addressing")
	}
	c, err := client.New(ctx, client.WithConfig(s.cfg))
	if err != nil {
		return nil, ctx, fmt.Errorf("connect to talos api: %w", err)
	}
	if len(nodes) > 0 {
		ctx = client.WithNodes(ctx, nodes...)
	}
	return c, ctx, nil
}

func newInsecureClient(ctx context.Context, endpoint string) (*client.Client, error) {
	c, err := client.New(ctx,
		client.WithEndpoints(endpoint),
		client.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}), //nolint:gosec
	)
	if err != nil {
		return nil, fmt.Errorf("connect to %s in maintenance mode: %w", endpoint, err)
	}
	return c, nil
}

// Stages exposes the runtime.MachineStage constants this package needs so
// callers do not have to import the runtime resources package directly.
const (
	StageMaintenance = runtime.MachineStageMaintenance
	StageRunning     = runtime.MachineStageRunning
)
