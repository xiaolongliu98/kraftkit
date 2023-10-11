// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/labels"
	clog "github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/nerdctl/pkg/imgutil/dockerconfigresolver"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"

	"kraftkit.sh/archive"
	"kraftkit.sh/config"
	"kraftkit.sh/log"
)

const (
	ContainerdGCLayerPrefix   = "containerd.io/gc.ref.content.l"
	ContainerdGCContentPrefix = "containerd.io/gc.ref.content"
	KraftKitLabelPrefix       = "kraftkit.sh/oci."
	KraftKitLabelMediaType    = KraftKitLabelPrefix + "mediaType"
)

type ContainerdHandler struct {
	client    *containerd.Client
	namespace string
	auths     map[string]config.AuthConfig
}

// NewContainerdHandler creates a Resolver-compatible interface given the
// containerd address and namespace.
func NewContainerdHandler(ctx context.Context, address, namespace string, auths map[string]config.AuthConfig, opts ...containerd.ClientOpt) (context.Context, *ContainerdHandler, error) {
	client, err := containerd.New(address, opts...)
	if err != nil {
		return nil, nil, err
	}

	if namespace == "" {
		namespace = "default"
	}

	// Swap containerd's internal logger with our io.Writer which can be replaced
	// with WithLogger
	clog.G(ctx).Logger.Out = log.G(ctx).Out
	clog.G(ctx).Logger.Formatter = log.G(ctx).Formatter
	clog.G(ctx).Logger.Level = log.G(ctx).Level

	return ctx, &ContainerdHandler{
		client:    client,
		namespace: namespace,
		auths:     auths,
	}, nil
}

// NewContainerdWithClient create a containerd Resolver-compatible with an
// existing containerd client connection.
func NewContainerdWithClient(ctx context.Context, client *containerd.Client) (context.Context, *ContainerdHandler, error) {
	if client == nil {
		return nil, nil, fmt.Errorf("no containerd client provided")
	}

	return ctx, &ContainerdHandler{client: client}, nil
}

// lease creates a lease which can be closed to enable asynchronous
// communication with containerd
func (handle *ContainerdHandler) lease(ctx context.Context) (context.Context, func(context.Context) error, error) {
	ctx, done, err := handle.client.WithLease(namespaces.WithNamespace(ctx, handle.namespace))
	if err != nil {
		return nil, nil, err
	}

	// Swap containerd's internal logger with KraftKit's
	ctx = clog.WithLogger(ctx, log.G(ctx).WithContext(ctx))

	return ctx, done, nil
}

// DigestExists implements DigestResolver.
func (handle *ContainerdHandler) DigestExists(ctx context.Context, dgst digest.Digest) (exists bool, err error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return false, err
	}

	defer func() {
		err = combineErrors(err, done(ctx))
	}()

	if _, err := handle.client.ContentStore().Info(ctx, dgst); err != nil {
		return false, err
	}

	return true, nil
}

// PullDigest implements DigestPuller.
func (handle *ContainerdHandler) PullDigest(ctx context.Context, mediaType, fullref string, dgst digest.Digest, plat *ocispec.Platform, onProgress func(float64)) error {
	resolver, err := dockerconfigresolver.New(
		ctx,
		strings.Split(fullref, "/")[0],
		dockerconfigresolver.WithSkipVerifyCerts(true),
		dockerconfigresolver.WithAuthCreds(func(domain string) (string, string, error) {
			auth, ok := handle.auths[domain]
			if !ok {
				return "", "", nil
			}

			return auth.User, auth.Token, nil
		}),
	)
	if err != nil {
		return err
	}

	return handle.client.Push(
		namespaces.WithNamespace(ctx, handle.namespace),
		fullref,
		ocispec.Descriptor{
			Digest:    dgst,
			MediaType: mediaType,
		},
		containerd.WithResolver(resolver),
	)
}

// SaveDescriptor implements DescriptorSaver.
func (handle *ContainerdHandler) SaveDescriptor(ctx context.Context, fullref string, desc ocispec.Descriptor, reader io.Reader, onProgress func(float64)) (err error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return err
	}

	cs := handle.client.ContentStore()

	defer func() {
		err = combineErrors(err, done(ctx))
	}()

	writer, err := content.OpenWriter(
		ctx,
		cs,
		content.WithDescriptor(desc),
		content.WithRef(desc.Digest.String()),
	)
	if err != nil {
		return err
	}

	defer writer.Close()

	log.G(ctx).WithFields(logrus.Fields{
		"mediaType": desc.MediaType,
		"digest":    desc.Digest.String(),
	}).Tracef("oci: copying")

	var tee io.Reader
	var cache bytes.Buffer
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex:
		tee = io.TeeReader(reader, &cache)
	default:
		tee = reader
	}

	if err := content.Copy(ctx,
		writer,
		tee,
		desc.Size,
		desc.Digest,
		// The use of this label is a hack to prevent containerd's garbage collector
		// from picking up and removing unreferenced content.
		content.WithLabels(map[string]string{
			"containerd.io/gc.root": "true",
		}),
	); err != nil {
		return err
	}

	// Post-processing for special media types which have additional metadata
	// associated with the digest.
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest:
		log.G(ctx).WithFields(logrus.Fields{
			"ref": fullref,
		}).Trace("oci: saving manifest")

		manifest := ocispec.Manifest{}
		if err := json.NewDecoder(&cache).Decode(&manifest); err != nil {
			return err
		}

		ref, err := name.ParseReference(fullref)
		if err != nil {
			return err
		}

		labels := map[string]string{
			KraftKitLabelMediaType: desc.MediaType,
			fmt.Sprintf("%s.%s", labels.LabelDistributionSource, ref.Context().RegistryStr()): ref.Context().RepositoryStr(),
		}

		// Add garbage collection prevention tags, reference all layers that are
		// part of this manifest.  See [0] for reference.
		//
		// [0]: https://github.com/containerd/containerd/blob/v1.7.6/docs/content-flow.md#manifest-labels
		for i, l := range manifest.Layers {
			labels[fmt.Sprintf("%s.%d", ContainerdGCLayerPrefix, i)] = l.Digest.String()
		}

		labels[fmt.Sprintf("%s.%d", ContainerdGCLayerPrefix, len(manifest.Layers))] = manifest.Config.Digest.String()

		updatedFields := make([]string, 0)

		for k, v := range labels {
			log.G(ctx).WithFields(logrus.Fields{
				k:     v,
				"ref": desc.Digest,
			}).Trace("oci: labelling")

			updatedFields = append(updatedFields, fmt.Sprintf("labels.%s", k))
		}

		if _, err := handle.client.ContentStore().Update(ctx, content.Info{
			Digest: digest.Digest(desc.Digest),
			Labels: labels,
		}, updatedFields...); err != nil {
			return err
		}

	default:
		labels := map[string]string{
			KraftKitLabelMediaType: desc.MediaType,
		}

		updatedFields := make([]string, 0)

		for k, v := range labels {
			log.G(ctx).WithFields(logrus.Fields{
				k:     v,
				"ref": desc.Digest,
			}).Trace("oci: labelling")

			updatedFields = append(updatedFields, fmt.Sprintf("labels.%s", k))
		}

		if _, err := handle.client.ContentStore().Update(ctx, content.Info{
			Digest: digest.Digest(desc.Digest),
			Labels: labels,
		}, updatedFields...); err != nil {
			return err
		}
	}

	return nil
}

// ResolveManifest implements ManifestResolver.
func (handle *ContainerdHandler) ResolveManifest(ctx context.Context, _ string, digest digest.Digest) (*ocispec.Manifest, error) {
	return ResolveContainerdObjectFromDigest[ocispec.Manifest](ctx, handle, digest)
}

// ListManifests implements DigestResolver.
func (handle *ContainerdHandler) ListManifests(ctx context.Context) (manifests map[string]*ocispec.Manifest, err error) {
	return ListContainerdObjectsByType[ocispec.Manifest](ctx, ocispec.MediaTypeImageManifest, handle)
}

func (handle *ContainerdHandler) DeleteManifest(ctx context.Context, fullref string, dgst digest.Digest) error {
	manifest, err := handle.ResolveManifest(ctx, fullref, dgst)
	if err != nil {
		return fmt.Errorf("could not resolve manifest: %w", err)
	}

	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, done(ctx))
	}()

	cs := handle.client.ContentStore()

	if err := cs.Delete(ctx, manifest.Config.Digest); err != nil {
		return fmt.Errorf("could not delete config from manifest '%s': %w", dgst.String(), err)
	}

	for _, layer := range manifest.Layers {
		if err := cs.Delete(ctx, layer.Digest); err != nil {
			return fmt.Errorf("could not delete layer from manifest '%s': %w", dgst.String(), err)
		}
	}

	return cs.Delete(ctx, dgst)
}

// SaveDigest implements DigestSaver.
func (handle *ContainerdHandler) SaveDigest(ctx context.Context, ref string, desc ocispec.Descriptor, reader io.Reader, onProgress func(float64)) (err error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return err
	}

	defer func() {
		err = combineErrors(err, done(ctx))
	}()

	writer, err := content.OpenWriter(
		ctx,
		handle.client.ContentStore(),
		content.WithDescriptor(desc),
		content.WithRef(desc.Digest.String()),
	)
	if err != nil {
		return err
	}

	log.G(ctx).WithFields(logrus.Fields{
		"mediaType": desc.MediaType,
		"digest":    desc.Digest.String(),
	}).Tracef("oci: copying")

	var tee io.Reader
	var cache bytes.Buffer
	if desc.MediaType == ocispec.MediaTypeImageManifest {
		tee = io.TeeReader(reader, &cache)
	} else {
		tee = reader
	}

	if err := content.Copy(ctx, writer, tee, desc.Size, desc.Digest); err != nil {
		return err
	}

	// Write the image and the various parentage tags
	is := handle.client.ImageService()

	switch desc.MediaType {
	// case ociimages.MediaTypeDockerSchema2Manifest,
	// 			ocispec.MediaTypeImageManifest,
	// 			ociimages.MediaTypeDockerSchema2ManifestList,
	// 			ocispec.MediaTypeImageIndex:
	case ocispec.MediaTypeImageManifest:
		// ref, ok := desc.Annotations[ociimages.AnnotationImageName]
		// if !ok {
		// 	return fmt.Errorf("cannot push image layer without image annotation")
		// }

		log.G(ctx).WithFields(logrus.Fields{
			"ref": ref,
		}).Trace("oci: indexing")

		manifest := ocispec.Manifest{}
		if err := json.NewDecoder(&cache).Decode(&manifest); err != nil {
			return err
		}

		// Add garbage prevention tags
		labels := map[string]string{}
		for i, l := range manifest.Layers {
			labels[fmt.Sprintf("%s.%d", ContainerdGCLayerPrefix, i)] = l.Digest.String()
		}

		labels[fmt.Sprintf("%s.%d", ContainerdGCLayerPrefix, len(manifest.Layers))] = manifest.Config.Digest.String()

		var image images.Image
		existingImage, err := is.Get(ctx, ref)

		if err != nil || existingImage.Target.Digest.String() == "" {
			log.G(ctx).Trace("oci: creating new image")
			image = images.Image{
				Name:      ref,
				Labels:    nil,
				Target:    desc,
				CreatedAt: time.Now(),
				UpdatedAt: time.Time{},
			}
			_, err = is.Create(ctx, image)
		} else {
			log.G(ctx).Trace("oci: updating existing image")
			image = images.Image{
				Name:      ref,
				Labels:    nil,
				Target:    desc,
				UpdatedAt: time.Time{},
			}
			_, err = is.Update(ctx, image)
		}
		if err != nil {
			return err
		}

		updatedFields := make([]string, 0)

		for k, v := range labels {
			log.G(ctx).WithFields(logrus.Fields{
				k:     v,
				"ref": image.Target.Digest,
			}).Trace("oci: labelling")

			updatedFields = append(updatedFields, fmt.Sprintf("labels.%s", k))
		}

		if _, err := handle.client.ContentStore().Update(ctx, content.Info{
			Digest: digest.Digest(desc.Digest),
			Labels: labels,
		}, updatedFields...); err != nil {
			return err
		}
	}

	return nil
}

// ResolveImage implements ImageResolver.
func (handle *ContainerdHandler) ResolveImage(ctx context.Context, fullref string) (*ocispec.Image, error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = combineErrors(err, done(ctx))
	}()

	containerdImage, err := handle.client.GetImage(ctx, fullref)
	if err != nil {
		return nil, err
	}

	image, err := containerdImage.Spec(ctx)
	if err != nil {
		return nil, err
	}

	return &image, nil
}

// FetchImage implements ImageFetcher.
func (handle *ContainerdHandler) FetchImage(ctx context.Context, ref, plat string, onProgress func(float64)) (err error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return err
	}

	defer func() {
		err = combineErrors(err, done(ctx))
	}()

	progress := make(chan struct{})
	ongoing := newJobs(ref)

	go func() {
		handle.reportProgress(ctx, ongoing, handle.client.ContentStore(), onProgress)
		close(progress)
	}()

	resolver, err := dockerconfigresolver.New(
		ctx,
		strings.Split(ref, "/")[0],
		dockerconfigresolver.WithSkipVerifyCerts(true),
		dockerconfigresolver.WithAuthCreds(func(domain string) (string, string, error) {
			auth, ok := handle.auths[domain]
			if !ok {
				return "", "", nil
			}

			return auth.User, auth.Token, nil
		}),
	)
	if err != nil {
		return err
	}

	ropts := []containerd.RemoteOpt{
		containerd.WithImageHandler(images.HandlerFunc(func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			if desc.MediaType != images.MediaTypeDockerSchema1Manifest {
				ongoing.Add(desc)
			}

			return nil, nil
		})),
		containerd.WithResolver(resolver),
	}

	if plat != "" {
		ropts = append(ropts, containerd.WithPlatform(plat))
	}

	// Fetch the image
	_, err = handle.client.Fetch(ctx, ref, ropts...)
	if err != nil {
		return err
	}

	<-progress

	return nil
}

// statusInfo holds the status info for an upload or download
type statusInfo struct {
	Ref       string
	Status    string
	Offset    int64
	Total     int64
	StartedAt time.Time
	UpdatedAt time.Time
}

// reportProgress uses the internal containerd store and live status monitoring
// in order to determine the overall progress of downloading multiple layers for
// a singlely specified OCI image which reports progress by invoking the
// `onProgress` callback method.
func (handle *ContainerdHandler) reportProgress(ctx context.Context, ongoing *jobs, cs content.Store, onProgress func(progress float64)) {
	// TODO: This implementation is based on containerd's `ctr content fetch`
	// implementation which can be found at:
	//
	//   https://github.com/containerd/containerd/blob/8ec1fc7/cmd/ctr/commands/content/fetch.go#L219-L336
	//
	// However, this implementation does not work correctly.  It seems that the
	// `active.Offset` attribute is reporting too little or `active.Total` is too
	// high and so the progress monitor shows progress download of 1-5% only.  In
	// KraftKit's progress meter (ui.paraprogress) and once this download is
	// complete (and the correct signal/channels are updated) the meter will jump
	// to 100% (as is desired by the package).  However, ultimately, this does not
	// feedback to the user the right information.  This implementation should be
	// more carefully inspected to determine why Offset and Total are incorrect.

	var (
		ticker   = time.NewTicker(100 * time.Millisecond)
		start    = time.Now()
		statuses = map[string]statusInfo{}
		done     bool
	)
	defer ticker.Stop()

outer:
	for {
		select {
		case <-ticker.C:
			resolved := "resolved"
			if !ongoing.IsResolved() {
				resolved = "resolving"
			}

			statuses[ongoing.name] = statusInfo{
				Ref:    ongoing.name,
				Status: resolved,
			}

			keys := []string{ongoing.name}

			// now, update the items in jobs that are not in active
			for _, j := range ongoing.Jobs() {
				key := remotes.MakeRefKey(ctx, j)

				activeSeen := map[string]struct{}{}
				if !done {
					activeStatuses, err := cs.ListStatuses(ctx, fmt.Sprintf("ref==%s", key))
					if err != nil {
						log.G(ctx).WithError(err).Error("active check failed")
						continue
					}

					// update status of active entries!
					for _, active := range activeStatuses {
						statuses[active.Ref] = statusInfo{
							Ref:       active.Ref,
							Status:    "downloading",
							Offset:    active.Offset,
							Total:     active.Total,
							StartedAt: active.StartedAt,
							UpdatedAt: active.UpdatedAt,
						}
						activeSeen[active.Ref] = struct{}{}
					}
				}

				keys = append(keys, key)
				if _, ok := activeSeen[key]; ok {
					continue
				}

				status, ok := statuses[key]
				if !done && (!ok || status.Status == "downloading") {
					info, err := cs.Info(ctx, j.Digest)
					if err != nil {
						if !errdefs.IsNotFound(err) {
							log.G(ctx).WithError(err).Error("failed to get content info")
							continue outer
						} else {
							statuses[key] = statusInfo{
								Ref:    key,
								Status: "waiting",
							}
						}
					} else if info.CreatedAt.After(start) {
						statuses[key] = statusInfo{
							Ref:       key,
							Status:    "done",
							UpdatedAt: info.CreatedAt,
							Total:     0,
						}
					} else {
						statuses[key] = statusInfo{
							Ref:    key,
							Status: "exists",
							Total:  0,
						}
					}
				} else if done {
					if ok {
						if status.Status != "done" && status.Status != "exists" {
							status.Status = "done"
							statuses[key] = status
						}
					} else {
						statuses[key] = statusInfo{
							Ref:    key,
							Status: "done",
							Total:  0,
						}
					}
				}
			}

			var offset int64 = 0
			var total int64 = 0
			var exists int = 0
			for _, status := range statuses {
				if status.Status == "exists" ||
					status.Status == "resolved" ||
					status.Status == "done" {
					exists++
				}
				if status.Total > 0 {
					offset += status.Offset
					total += status.Total
				}
			}

			if onProgress != nil {
				onProgress(float64(offset) / float64(total))
			}

			if done || (len(statuses) == exists) {
				return
			}
		case <-ctx.Done():
			done = true // allow ui to update once more
		}
	}
}

// PushImage implements ImagePusher.
func (handle *ContainerdHandler) PushImage(ctx context.Context, ref string, target *ocispec.Descriptor) error {
	resolver, err := dockerconfigresolver.New(
		ctx,
		strings.Split(ref, "/")[0],
		dockerconfigresolver.WithSkipVerifyCerts(true),
		dockerconfigresolver.WithAuthCreds(func(domain string) (string, string, error) {
			auth, ok := handle.auths[domain]
			if !ok {
				return "", "", nil
			}

			return auth.User, auth.Token, nil
		}),
	)
	if err != nil {
		return err
	}

	return handle.client.Push(
		namespaces.WithNamespace(ctx, handle.namespace),
		ref,
		*target,
		containerd.WithResolver(resolver),
	)
}

// UnpackImage implements ImageUnpacker.
func (handle *ContainerdHandler) UnpackImage(ctx context.Context, ref string, dest string) (err error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return err
	}

	defer func() {
		err = combineErrors(err, done(ctx))
	}()

	img, err := handle.client.ImageService().Get(ctx, ref)
	if err != nil {
		return err
	}

	i := containerd.NewImage(handle.client, img)

	// TODO: We need to pass the architecture, platform and any desired KConfig
	// values via the platform specifier:
	// i := containerd.NewImageWithPlatform(
	// 	handle.client,
	// 	img,
	// 	platforms.Only(ocispec.Platform{
	// 	// TODO!
	// 	})),
	// )

	if err = i.Unpack(ctx, containerd.DefaultSnapshotter); err != nil {
		return err
	}

	isUnpacked, err := i.IsUnpacked(ctx, containerd.DefaultSnapshotter)
	if err != nil {
		return err
	}

	if !isUnpacked {
		return fmt.Errorf("empty image")
	}

	// TODO(nderjung): This is where we could used media-types to extract the
	// right files.

	layers, err := i.RootFS(ctx)
	if err != nil {
		return err
	}

	for _, layer := range layers {
		log.G(ctx).WithField("digest", layer.String()).Trace("extract layer")

		ra, err := i.ContentStore().ReaderAt(ctx, ocispec.Descriptor{Digest: layer})
		if err != nil {
			return err
		}

		if err := archive.Untar(content.NewReader(ra), dest); err != nil {
			return err
		}

		ra.Close()
	}

	return nil
}

// FinalizeImage implements ImageFinalizer.
func (handle *ContainerdHandler) FinalizeImage(ctx context.Context, image ocispec.Image) error {
	return fmt.Errorf("not implemented: oci.handler.ContainerdHandler.FinalizeImage")
}

// combineErrors is a helper for handling multiple potential errors, combining
// them as necessary. It is meant to be used in a deferred function.
func combineErrors(original, additional error) error {
	switch {
	case additional == nil:
		return original
	case original != nil:
		return fmt.Errorf("%w. Additionally: %w", original, additional)
	default:
		return additional
	}
}

// readBlob accepts containerd's content readerAt and returns the byte slice
// data or an error.
func readBlob(readerAt content.ReaderAt) ([]byte, error) {
	blob := make([]byte, readerAt.Size())

	n, err := readerAt.ReadAt(blob, 0)
	if err == io.EOF {
		if int64(n) != readerAt.Size() {
			err = io.ErrUnexpectedEOF
		} else {
			err = nil
		}
	}

	return blob, err
}

// ResolveContainerdObjectFromDigest is a generic method that traverses
// containerd's content store and attempts to retrieve an object from the store
// based on its type and digest.  This is accomplished by attempting to
// type-cast the object into the relevant generic T.
func ResolveContainerdObjectFromDigest[T any](ctx context.Context, handle *ContainerdHandler, digest digest.Digest) (*T, error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = errors.Join(err, done(ctx))
	}()

	cs := handle.client.ContentStore()
	var t *T

	if err := cs.Walk(ctx, func(info content.Info) error {
		if digest.String() != info.Digest.String() {
			return nil // Do not return an error, simply "continue"
		}

		readerAt, err := cs.ReaderAt(ctx, ocispec.Descriptor{
			Digest: info.Digest,
		})
		if err != nil {
			return err
		}

		defer readerAt.Close()

		blob, err := readBlob(readerAt)
		if err != nil {
			return nil // Do not return an error, simply "continue"
		}

		if err := json.Unmarshal(blob, &t); err != nil {
			return nil // Do not return an error, simply "continue"
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if t == nil {
		return nil, fmt.Errorf("digest '%s' not found", digest.String())
	}

	return t, nil
}

// ListContainerdObjectsByType is a utility method which iterates across all
// containerd objects in the store and attempts to typecast the object to the
// type T.  A successful type conversion is added to the hashmap which is
// ordered by digest.
func ListContainerdObjectsByType[T any](ctx context.Context, mediaType string, handle *ContainerdHandler) (map[string]*T, error) {
	ctx, done, err := handle.lease(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = errors.Join(err, done(ctx))
	}()

	cs := handle.client.ContentStore()
	objects := make(map[string]*T, 0)

	if err := cs.Walk(ctx, func(info content.Info) error {
		if mediaType != "" {
			if labelMediaType, ok := info.Labels[KraftKitLabelMediaType]; !ok || labelMediaType != mediaType {
				return nil // Do not return an error, simply "continue"
			}
		}

		readerAt, err := cs.ReaderAt(ctx, ocispec.Descriptor{
			Digest: info.Digest,
		})
		if err != nil {
			return err
		}

		defer readerAt.Close()

		blob, err := readBlob(readerAt)
		if err != nil {
			return nil // Do not return an error, simply "continue"
		}

		var t *T

		if err := json.Unmarshal(blob, &t); err != nil {
			return nil // Do not return an error, simply "continue"
		}

		objects[info.Digest.String()] = t

		return nil
	}); err != nil {
		return nil, err
	}

	return objects, nil
}
