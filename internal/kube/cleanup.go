// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package kube

import (
	"context"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// excludedResourceTypes are types that fail or stall a list-with-verbs=list
// query and that we never need to delete during CNI cleanup. Skipping them
// avoids spurious errors during the Flannel/kube-proxy purge.
var excludedResourceTypes = map[string]struct{}{
	"componentstatuses": {},
	"validatingadmissionpolicies.admissionregistration.k8s.io":        {},
	"validatingadmissionpolicybindings.admissionregistration.k8s.io":  {},
	"nodes.metrics.k8s.io":                                            {},
	"pods.metrics.k8s.io":                                             {},
}

// PurgeBySelector deletes every listable resource (cluster-scoped and namespaced
// in the given namespace) matching the label selector. This replaces the
// `kubectl api-resources --verbs=list` plus `kubectl delete` shell pipeline used
// to remove the default CNI's resources.
func (c *Client) PurgeBySelector(ctx context.Context, namespace, selector string) error {
	clusterGVRs, namespacedGVRs, err := c.discoverDeletableGVRs(ctx)
	if err != nil {
		return err
	}
	for _, gvr := range clusterGVRs {
		if err := c.tryDeleteCollection(ctx, gvr, "", &selector, ""); err != nil {
			return err
		}
	}
	for _, gvr := range namespacedGVRs {
		if err := c.tryDeleteCollection(ctx, gvr, namespace, &selector, ""); err != nil {
			return err
		}
	}
	return nil
}

// PurgeByName deletes a single named resource, by name, across every
// listable type in scope. This replaces the `kubectl delete <types> kube-proxy`
// pattern from the Python original.
func (c *Client) PurgeByName(ctx context.Context, namespace, name string) error {
	clusterGVRs, namespacedGVRs, err := c.discoverDeletableGVRs(ctx)
	if err != nil {
		return err
	}
	for _, gvr := range clusterGVRs {
		if err := c.tryDeleteCollection(ctx, gvr, "", nil, name); err != nil {
			return err
		}
	}
	for _, gvr := range namespacedGVRs {
		if err := c.tryDeleteCollection(ctx, gvr, namespace, nil, name); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) discoverDeletableGVRs(_ context.Context) (cluster, namespaced []GroupVersionResource, err error) {
	apis, err := c.Discovery.ServerPreferredResources()
	if err != nil {
		// ServerPreferredResources can return a partial result with an error
		// when some API groups are unhealthy. As long as we have data we keep
		// going; the caller can still complete cleanup of healthy types.
		if len(apis) == 0 {
			return nil, nil, fmt.Errorf("discover api resources: %w", err)
		}
	}
	for _, list := range apis {
		gv, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			continue
		}
		for _, r := range list.APIResources {
			if !slices.Contains(r.Verbs, "list") || !slices.Contains(r.Verbs, "delete") {
				continue
			}
			// Subresources are exposed as "<parent>/<sub>" and are not deletable
			// as standalone collections.
			if strings.Contains(r.Name, "/") {
				continue
			}
			fullName := r.Name
			if gv.Group != "" {
				fullName = r.Name + "." + gv.Group
			}
			if _, skip := excludedResourceTypes[fullName]; skip {
				continue
			}
			gvr := GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: r.Name}
			if r.Namespaced {
				namespaced = append(namespaced, gvr)
			} else {
				cluster = append(cluster, gvr)
			}
		}
	}
	return cluster, namespaced, nil
}


func (c *Client) tryDeleteCollection(ctx context.Context, gvr GroupVersionResource, namespace string, selector *string, name string) error {
	ri := c.namespacedOrCluster(gvr, namespace)
	if name != "" {
		return c.DeleteIfExists(ctx, gvr, namespace, name)
	}
	if selector == nil {
		return nil
	}
	err := ri.DeleteCollection(ctx,
		metav1.DeleteOptions{},
		metav1.ListOptions{LabelSelector: *selector},
	)
	if err == nil {
		return nil
	}
	// Tolerate types that the API rejects for collection delete (e.g. read-only
	// virtual resources) and missing-resource errors.
	if apierrors.IsMethodNotSupported(err) || apierrors.IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("delete %s in %q with selector %q: %w", gvr.Resource, namespace, *selector, err)
}
