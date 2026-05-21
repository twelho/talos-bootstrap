// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package kube

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// GroupVersionResource is a small alias to keep the public API of this
// package independent of k8s.io/apimachinery types.
type GroupVersionResource struct {
	Group    string
	Version  string
	Resource string
}

func (g GroupVersionResource) toUnstructuredGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: g.Group, Version: g.Version, Resource: g.Resource}
}

// ApplyServerSide performs a server-side apply of every resource in objs with
// force-conflicts enabled, mirroring `kubectl apply --server-side --force-conflicts`.
// The REST mapper is used to translate kind to resource and to detect cluster vs
// namespaced scope.
func (c *Client) ApplyServerSide(ctx context.Context, objs []*unstructured.Unstructured) error {
	for _, obj := range objs {
		if err := c.applyOne(ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) applyOne(ctx context.Context, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	mapping, err := c.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return fmt.Errorf("rest mapping for %s: %w", gvk, err)
	}
	data, err := obj.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal %s/%s: %w", gvk.Kind, obj.GetName(), err)
	}

	var ri dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		ns := obj.GetNamespace()
		if ns == "" {
			ns = "default"
		}
		ri = c.Dynamic.Resource(mapping.Resource).Namespace(ns)
	} else {
		ri = c.Dynamic.Resource(mapping.Resource)
	}

	force := true
	_, err = ri.Patch(ctx, obj.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{
		FieldManager: FieldManager,
		Force:        &force,
	})
	if err != nil {
		return fmt.Errorf("apply %s/%s: %w", gvk.Kind, obj.GetName(), err)
	}
	return nil
}

// DeleteByLabel deletes every instance of the given resource matching a label
// selector. Missing resources or 404s on individual deletes are tolerated so
// the operation is idempotent.
func (c *Client) DeleteByLabel(ctx context.Context, gvr GroupVersionResource, namespace, selector string) error {
	sel, err := labels.Parse(selector)
	if err != nil {
		return fmt.Errorf("parse selector %q: %w", selector, err)
	}
	ri := c.namespacedOrCluster(gvr, namespace)
	return ri.DeleteCollection(ctx,
		metav1.DeleteOptions{},
		metav1.ListOptions{LabelSelector: sel.String()},
	)
}

// DeleteIfExists deletes a single named resource and returns nil if it does
// not exist.
func (c *Client) DeleteIfExists(ctx context.Context, gvr GroupVersionResource, namespace, name string) error {
	ri := c.namespacedOrCluster(gvr, namespace)
	err := ri.Delete(ctx, name, metav1.DeleteOptions{})
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("delete %s/%s: %w", gvr.Resource, name, err)
}

func (c *Client) namespacedOrCluster(gvr GroupVersionResource, namespace string) dynamic.ResourceInterface {
	gv := gvr.toUnstructuredGVR()
	if namespace == "" {
		return c.Dynamic.Resource(gv)
	}
	return c.Dynamic.Resource(gv).Namespace(namespace)
}
