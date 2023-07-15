#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-310.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(146649);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id("CVE-2019-10214", "CVE-2020-10696");

  script_name(english:"openSUSE Security Update : buildah / libcontainers-common / podman (openSUSE-2021-310)");
  script_summary(english:"Check for the openSUSE-2021-310 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for buildah, libcontainers-common, podman fixes the
following issues :

Changes in libcontainers-common :

  - Update common to 0.33.0

  - Update image to 5.9.0

  - Update podman to 2.2.1

  - Update storage to 1.24.5

  - Switch to seccomp profile provided by common instead of
    podman

  - Update containers.conf to match latest version

Changes in buildah :

Update to version 1.19.2 :

  - Update vendor of containers/storage and
    containers/common

  - Buildah inspect should be able to inspect manifests

  - Make buildah push support pushing manifests lists and
    digests

  - Fix handling of TMPDIR environment variable

  - Add support for --manifest flags

  - Upper directory should match mode of destination
    directory

  - Only grab the OS, Arch if the user actually specified
    them

  - Use --arch and --os and --variant options to select
    architecture and os

  - Cirrus: Track libseccomp and golang version

  - copier.PutOptions: add an 'IgnoreDevices' flag

  - fix: `rmi --prune` when parent image is in store.

  - build(deps): bump github.com/containers/storage from
    1.24.3 to 1.24.4

  - build(deps): bump github.com/containers/common from
    0.31.1 to 0.31.2

  - Allow users to specify stdin into containers

  - Drop log message on failure to mount on /sys file
    systems to info

  - Spelling

  - SELinux no longer requires a tag.

  - build(deps): bump github.com/opencontainers/selinux from
    1.6.0 to 1.8.0

  - build(deps): bump github.com/containers/common from
    0.31.0 to 0.31.1

  - Update nix pin with `make nixpkgs`

  - Switch references of /var/run -> /run

  - Allow FROM to be overriden with from option

  - copier: don't assume we can chroot() on Unixy systems

  - copier: add PutOptions.NoOverwriteDirNonDir,
    Get/PutOptions.Rename

  - copier: handle replacing directories with
    not-directories

  - copier: Put: skip entries with zero-length names

  - build(deps): bump github.com/containers/storage from
    1.24.2 to 1.24.3

  - Add U volume flag to chown source volumes

  - Turn off PRIOR_UBUNTU Test until vm is updated

  - pkg, cli: rootless uses correct isolation

  - build(deps): bump github.com/onsi/gomega from 1.10.3 to
    1.10.4

  - update installation doc to reflect current status

  - Move away from using docker.io

  - enable short-name aliasing

  - build(deps): bump github.com/containers/storage from
    1.24.1 to 1.24.2

  - build(deps): bump github.com/containers/common from
    0.30.0 to 0.31.0

  - Throw errors when using bogus --network flags

  - pkg/supplemented test: replace our null blobinfocache

  - build(deps): bump github.com/containers/common from
    0.29.0 to 0.30.0

  - inserts forgotten quotation mark

  - Not prefer use local image create/add manifest

  - Add container information to .containerenv

  - Add --ignorefile flag to use alternate .dockerignore
    flags

  - Add a source debug build

  - Fix crash on invalid filter commands

  - build(deps): bump github.com/containers/common from
    0.27.0 to 0.29.0

  - Switch to using containers/common pkg's

  - fix: non-portable shebang #2812

  - Remove copy/paste errors that leaked `Podman` into man
    pages.

  - Add suggests cpp to spec file

  - Apply suggestions from code review

  - update docs for debian testing and unstable

  - imagebuildah: disable pseudo-terminals for RUN

  - Compute diffID for mapped-layer at creating image source

  - intermediateImageExists: ignore images whose history we
    can't read

  - Bump to v1.19.0-dev

  - build(deps): bump github.com/containers/common from
    0.26.3 to 0.27.0

  - Fix testing error caused by simultanious merge

  - Vendor in containers/storage v1.24.0

  - short-names aliasing

  - Add --policy flag to buildah pull

  - Stop overwrapping and stuttering

  - copier.Get(): ignore ENOTSUP/ENOSYS when listing xattrs

  - Run: don't forcibly disable UTS namespaces in rootless
    mode

  - test: ensure non-directory in a Dockerfile path is
    handled correctly

  - Add a few tests for `pull` command

  - Fix buildah config --cmd to handle array

  - build(deps): bump github.com/containers/storage from
    1.23.8 to 1.23.9

  - Fix NPE when Dockerfile path contains non-directory
    entries

  - Update buildah bud man page from podman build man page

  - Move declaration of decryption-keys to common cli

  - Run: correctly call copier.Mkdir

  - util: digging UID/GID out of os.FileInfo should work on
    Unix

  - imagebuildah.getImageTypeAndHistoryAndDiffIDs: cache
    results

  - Verify userns-uid-map and userns-gid-map input

  - Use CPP, CC and flags in dep check scripts

  - Avoid overriding LDFLAGS in Makefile

  - ADD: handle --chown on URLs

  - Update nix pin with `make nixpkgs`

  - (*Builder).Run: MkdirAll: handle EEXIST error

  - copier: try to force loading of nsswitch modules before
    chroot()

  - fix MkdirAll usage

  - build(deps): bump github.com/containers/common from
    0.26.2 to 0.26.3

  - build(deps): bump github.com/containers/storage from
    1.23.7 to 1.23.8

  - Use osusergo build tag for static build

  - imagebuildah: cache should take image format into
    account

  - Bump to v1.18.0-dev

Update to version 1.17.1 :

  - copier.Get(): ignore ENOTSUP/ENOSYS when listing xattrs

  - copier: try to force loading of nsswitch modules before
    chroot()

  - ADD: handle --chown on URLs

  - imagebuildah: cache should take image format into
    account

  - Update CI configuration for the release-1.17 branch

added cni to requires as its needed for buildah to run 

Update to v1.17.0 (boo#1165184)

  - Handle cases where other tools mount/unmount containers

  - overlay.MountReadOnly: support RO overlay mounts

  - overlay: use fusermount for rootless umounts

  - overlay: fix umount

  - Switch default log level of Buildah to Warn. Users need
    to see these messages

  - Drop error messages about OCI/Docker format to Warning
    level

  - build(deps): bump github.com/containers/common from
    0.26.0 to 0.26.2

  - tests/testreport: adjust for API break in storage
    v1.23.6

  - build(deps): bump github.com/containers/storage from
    1.23.5 to 1.23.7

  - build(deps): bump github.com/fsouza/go-dockerclient from
    1.6.5 to 1.6.6

  - copier: put: ignore Typeflag='g'

  - Use curl to get repo file (fix #2714)

  - build(deps): bump github.com/containers/common from
    0.25.0 to 0.26.0

  - build(deps): bump github.com/spf13/cobra from 1.0.0 to
    1.1.1

  - Remove docs that refer to bors, since we're not using it

  - Buildah bud should not use stdin by default

  - bump containerd, docker, and golang.org/x/sys

  - Makefile: cross: remove windows.386 target

  - copier.copierHandlerPut: don't check length when there
    are errors

  - Stop excessive wrapping

  - CI: require that conformance tests pass

  - bump(github.com/openshift/imagebuilder) to v1.1.8

  - Skip tlsVerify insecure BUILD_REGISTRY_SOURCES

  - Fix build path wrong containers/podman#7993

  - refactor pullpolicy to avoid deps

  - build(deps): bump github.com/containers/common from
    0.24.0 to 0.25.0

  - CI: run gating tasks with a lot more memory

  - ADD and COPY: descend into excluded directories,
    sometimes

  - copier: add more context to a couple of error messages

  - copier: check an error earlier

  - copier: log stderr output as debug on success

  - Update nix pin with make nixpkgs

  - Set directory ownership when copied with ID mapping

  - build(deps): bump github.com/sirupsen/logrus from 1.6.0
    to 1.7.0

  - build(deps): bump github.com/containers/common from
    0.23.0 to 0.24.0

  - Cirrus: Remove bors artifacts

  - Sort build flag definitions alphabetically

  - ADD: only expand archives at the right time

  - Remove configuration for bors

  - Shell Completion for podman build flags

  - Bump c/common to v0.24.0

  - New CI check: xref --help vs man pages

  - CI: re-enable several linters

  - Move --userns-uid-map/--userns-gid-map description into
    buildah man page

  - add: preserve ownerships and permissions on ADDed
    archives

  - Makefile: tweak the cross-compile target

  - Bump containers/common to v0.23.0

  - chroot: create bind mount targets 0755 instead of 0700

  - Change call to Split() to safer SplitN()

  - chroot: fix handling of errno seccomp rules

  - build(deps): bump github.com/containers/image/v5 from
    5.5.2 to 5.6.0

  - Add In Progress section to contributing

  - integration tests: make sure tests run in
    $(topdir)/tests

  - Run(): ignore containers.conf's environment
    configuration

  - Warn when setting healthcheck in OCI format

  - Cirrus: Skip git-validate on branches

  - tools: update git-validation to the latest commit

  - tools: update golangci-lint to v1.18.0

  - Add a few tests of push command

  - Add(): fix handling of relative paths with no ContextDir

  - build(deps): bump github.com/containers/common from
    0.21.0 to 0.22.0

  - Lint: Use same linters as podman

  - Validate: reference HEAD

  - Fix buildah mount to display container names not ids

  - Update nix pin with make nixpkgs

  - Add missing --format option in buildah from man page

  - Fix up code based on codespell

  - build(deps): bump github.com/openshift/imagebuilder from
    1.1.6 to 1.1.7

  - build(deps): bump github.com/containers/storage from
    1.23.4 to 1.23.5

  - Improve buildah completions

  - Cirrus: Fix validate commit epoch

  - Fix bash completion of manifest flags

  - Uniform some man pages

  - Update Buildah Tutorial to address BZ1867426

  - Update bash completion of manifest add sub command

  - copier.Get(): hard link targets shouldn't be relative
    paths

  - build(deps): bump github.com/onsi/gomega from 1.10.1 to
    1.10.2

  - Pass timestamp down to history lines

  - Timestamp gets updated everytime you inspect an image

  - bud.bats: use absolute paths in newly-added tests

  - contrib/cirrus/lib.sh: don't use CN for the hostname

  - tests: Add some tests

  - Update manifest add man page

  - Extend flags of manifest add

  - build(deps): bump github.com/containers/storage from
    1.23.3 to 1.23.4

  - build(deps): bump github.com/onsi/ginkgo from 1.14.0 to
    1.14.1

  - Bump to v1.17.0-dev

  - CI: expand cross-compile checks

  - SLE: Remove unneeded patch: CVE-2019-10214.patch

Update to v1.16.2

  - fix build on 32bit arches

  - containerImageRef.NewImageSource(): don't always force
    timestamps

  - Add fuse module warning to image readme

  - Heed our retry delay option values when retrying
    commit/pull/push

  - Switch to containers/common for seccomp

  - Use --timestamp rather then --omit-timestamp

  - docs: remove outdated notice

  - docs: remove outdated notice

  - build-using-dockerfile: add a hidden --log-rusage flag

  - build(deps): bump github.com/containers/image/v5 from
    5.5.1 to 5.5.2

  - Discard ReportWriter if user sets options.Quiet

  - build(deps): bump github.com/containers/common from
    0.19.0 to 0.20.3

  - Fix ownership of content copied using COPY --from

  - newTarDigester: zero out timestamps in tar headers

  - Update nix pin with `make nixpkgs`

  - bud.bats: correct .dockerignore integration tests

  - Use pipes for copying

  - run: include stdout in error message

  - run: use the correct error for errors.Wrapf

  - copier: un-export internal types

  - copier: add Mkdir()

  - in_podman: don't get tripped up by $CIRRUS_CHANGE_TITLE

  - docs/buildah-commit.md: tweak some wording, add a --rm
    example

  - imagebuildah: don&rsquo;t blank out destination names
    when COPYing

  - Replace retry functions with common/pkg/retry

  - StageExecutor.historyMatches: compare timestamps using
    .Equal

  - Update vendor of containers/common

  - Fix errors found in coverity scan

  - Change namespace handling flags to better match podman
    commands

  - conformance testing: ignore
    buildah.BuilderIdentityAnnotation labels

  - Vendor in containers/storage v1.23.0

  - Add buildah.IsContainer interface

  - Avoid feeding run_buildah to pipe

  - fix(buildahimage): add xz dependency in buildah image

  - Bump github.com/containers/common from 0.15.2 to 0.18.0

  - Howto for rootless image building from OpenShift

  - Add --omit-timestamp flag to buildah bud

  - Update nix pin with `make nixpkgs`

  - Shutdown storage on failures

  - Handle COPY --from when an argument is used

  - Bump github.com/seccomp/containers-golang from 0.5.0 to
    0.6.0

  - Cirrus: Use newly built VM images

  - Bump github.com/opencontainers/runc from 1.0.0-rc91 to
    1.0.0-rc92

  - Enhance the .dockerignore man pages

  - conformance: add a test for COPY from subdirectory

  - fix bug manifest inspct

  - Add documentation for .dockerignore

  - Add BuilderIdentityAnnotation to identify buildah
    version

  - DOC: Add quay.io/containers/buildah image to README.md

  - Update buildahimages readme

  - fix spelling mistake in 'info' command result display

  - Don't bind /etc/host and /etc/resolv.conf if network is
    not present

  - blobcache: avoid an unnecessary NewImage()

  - Build static binary with `buildGoModule`

  - copier: split StripSetidBits into
    StripSetuidBit/StripSetgidBit/StripStickyBit

  - tarFilterer: handle multiple archives

  - Fix a race we hit during conformance tests

  - Rework conformance testing

  - Update 02-registries-repositories.md

  - test-unit: invoke cmd/buildah tests with --flags

  - parse: fix a type mismatch in a test

  - Fix compilation of tests/testreport/testreport

  - build.sh: log the version of Go that we're using

  - test-unit: increase the test timeout to 40/45 minutes

  - Add the 'copier' package

  - Fix & add notes regarding problematic language in
    codebase

  - Add dependency on github.com/stretchr/testify/require

  - CompositeDigester: add the ability to filter tar streams

  - BATS tests: make more robust

  - vendor golang.org/x/text@v0.3.3

  - Switch golang 1.12 to golang 1.13

  - imagebuildah: wait for stages that might not have even
    started yet

  - chroot, run: not fail on bind mounts from /sys

  - chroot: do not use setgroups if it is blocked

  - Set engine env from containers.conf

  - imagebuildah: return the right stage's image as the
    'final' image

  - Fix a help string

  - Deduplicate environment variables

  - switch containers/libpod to containers/podman

  - Bump github.com/containers/ocicrypt from 1.0.2 to 1.0.3

  - Bump github.com/opencontainers/selinux from 1.5.2 to
    1.6.0

  - Mask out /sys/dev to prevent information leak

  - linux: skip errors from the runtime kill

  - Mask over the /sys/fs/selinux in mask branch

  - Add VFS additional image store to container

  - tests: add auth tests

  - Allow 'readonly' as alias to 'ro' in mount options

  - Ignore OS X specific consistency mount option

  - Bump github.com/onsi/ginkgo from 1.13.0 to 1.14.0

  - Bump github.com/containers/common from 0.14.0 to 0.15.2

  - Rootless Buildah should default to IsolationOCIRootless

  - imagebuildah: fix inheriting multi-stage builds

  - Make imagebuildah.BuildOptions.Architecture/OS optional

  - Make imagebuildah.BuildOptions.Jobs optional

  - Resolve a possible race in
    imagebuildah.Executor.startStage()

  - Switch scripts to use containers.conf

  - Bump openshift/imagebuilder to v1.1.6

  - Bump go.etcd.io/bbolt from 1.3.4 to 1.3.5

  - buildah, bud: support --jobs=N for parallel execution

  - executor: refactor build code inside new function

  - Add bud regression tests

  - Cirrus: Fix missing htpasswd in registry img

  - docs: clarify the 'triples' format

  - CHANGELOG.md: Fix markdown formatting

  - Add nix derivation for static builds

Update to v1.15.1

  - Mask over the /sys/fs/selinux in mask branch

  - chroot: do not use setgroups if it is blocked

  - chroot, run: not fail on bind mounts from /sys

  - Allow 'readonly' as alias to 'ro' in mount options

  - Add VFS additional image store to container

  - vendor golang.org/x/text@v0.3.3

  - Make imagebuildah.BuildOptions.Architecture/OS optional

Update to v1.15.0

  - Add CVE-2020-10696 to CHANGELOG.md and changelog.txt

  - fix lighttpd example

  - remove dependency on openshift struct

  - Warn on unset build arguments

  - vendor: update seccomp/containers-golang to v0.4.1

  - Updated docs

  - clean up comments

  - update exit code for tests

  - Implement commit for encryption

  - implementation of encrypt/decrypt push/pull/bud/from

  - fix resolve docker image name as transport

  - Add preliminary profiling support to the CLI

  - Evaluate symlinks in build context directory

  - fix error info about get signatures for
    containerImageSource

  - Add Security Policy

  - Cirrus: Fixes from review feedback

  - imagebuildah: stages shouldn't count as their base
    images

  - Update containers/common v0.10.0

  - Add registry to buildahimage Dockerfiles

  - Cirrus: Use pre-installed VM packages + F32

  - Cirrus: Re-enable all distro versions

  - Cirrus: Update to F31 + Use cache images

  - golangci-lint: Disable gosimple

  - Lower number of golangci-lint threads

  - Fix permissions on containers.conf

  - Don't force tests to use runc

  - Return exit code from failed containers

  - cgroup_manager should be under [engine]

  - Use c/common/pkg/auth in login/logout

  - Cirrus: Temporarily disable Ubuntu 19 testing

  - Add containers.conf to stablebyhand build

  - Update gitignore to exclude test Dockerfiles

  - Remove warning for systemd inside of container

  - Add patch for CVE-2019-10214. boo#1144065

  + CVE-2019-10214.patch

Changes in podman :

Update to v2.2.1

  - Changes

  - Due to a conflict with a previously-removed field, we
    were forced to modify the way image volumes (mounting
    images into containers using

    --mount type=image) were handled in the database. As a
    result, containers created in Podman 2.2.0 with image
    volume will not have them in v2.2.1, and these
    containers will need to be re-created.

  - Bugfixes

  - Fixed a bug where rootless Podman would, on systems
    without the XDG_RUNTIME_DIR environment variable
    defined, use an incorrect path for the PID file of the
    Podman pause process, causing Podman to fail to start
    (#8539).

  - Fixed a bug where containers created using Podman v1.7
    and earlier were unusable in Podman due to JSON decode
    errors (#8613).

  - Fixed a bug where Podman could retrieve invalid cgroup
    paths, instead of erroring, for containers that were not
    running.

  - Fixed a bug where the podman system reset command would
    print a warning about a duplicate shutdown handler being
    registered.

  - Fixed a bug where rootless Podman would attempt to mount
    sysfs in circumstances where it was not allowed; some
    OCI runtimes (notably crun) would fall back to
    alternatives and not fail, but others (notably runc)
    would fail to run containers.

  - Fixed a bug where the podman run and podman create
    commands would fail to create containers from untagged
    images (#8558).

  - Fixed a bug where remote Podman would prompt for a
    password even when the server did not support password
    authentication (#8498).

  - Fixed a bug where the podman exec command did not move
    the Conmon process for the exec session into the correct
    cgroup.

  - Fixed a bug where shell completion for the ancestor
    option to podman ps --filter did not work correctly.

  - Fixed a bug where detached containers would not properly
    clean themselves up (or remove themselves if --rm was
    set) if the Podman command that created them was invoked
    with --log-level=debug.

  - API

  - Fixed a bug where the Compat Create endpoint for
    Containers did not properly handle the Binds and Mounts
    parameters in HostConfig.

  - Fixed a bug where the Compat Create endpoint for
    Containers ignored the Name query parameter.

  - Fixed a bug where the Compat Create endpoint for
    Containers did not properly handle the 'default' value
    for NetworkMode (this value is used extensively by
    docker-compose) (#8544).

  - Fixed a bug where the Compat Build endpoint for Images
    would sometimes incorrectly use the target query
    parameter as the image's tag.

  - Misc

  - Podman v2.2.0 vendored a non-released, custom version of
    the github.com/spf13/cobra package; this has been
    reverted to the latest upstream release to aid in
    packaging.

  - Updated the containers/image library to v5.9.0

Update to v2.2.0

  - Features

  - Experimental support for shortname aliasing has been
    added. This is not enabled by default, but can be turned
    on by setting the environment variable
    CONTAINERS_SHORT_NAME_ALIASING to on. Documentation is
    available here and here.

  - Initial support has been added for the podman network
    connect and podman network disconnect commands, which
    allow existing containers to modify what networks they
    are connected to. At present, these commands can only be
    used on running containers that did not specify
    --network=none when they were created.

  - The podman run command now supports the --network-alias
    option to set network aliases (additional names the
    container can be accessed at from other containers via
    DNS if the dnsname CNI plugin is in use). Aliases can
    also be added and removed using the new podman network
    connect and podman network disconnect commands. Please
    note that this requires a new release (v1.1.0) of the
    dnsname plugin, and will only work on newly-created CNI
    networks.

  - The podman generate kube command now features support
    for exporting container's memory and CPU limits (#7855).

  - The podman play kube command now features support for
    setting CPU and Memory limits for containers (#7742).

  - The podman play kube command now supports persistent
    volumes claims using Podman named volumes.

  - The podman play kube command now supports Kubernetes
    configmaps via the --configmap option (#7567).

  - The podman play kube command now supports a --log-driver
    option to set the log driver for created containers.

  - The podman play kube command now supports a --start
    option, enabled by default, to start the pod after
    creating it. This allows for podman play kube to be more
    easily used in systemd unitfiles.

  - The podman network create command now supports the
    --ipv6 option to enable dual-stack IPv6 networking for
    created networks (#7302).

  - The podman inspect command can now inspect pods,
    networks, and volumes, in addition to containers and
    images (#6757).

  - The --mount option for podman run and podman create now
    supports a new type, image, to mount the contents of an
    image into the container at a given location.

  - The Bash and ZSH completions have been completely
    reworked and have received significant enhancements!
    Additionally, support for Fish completions and
    completions for the podman-remote executable have been
    added.

  - The --log-opt option for podman create and podman run
    now supports the max-size option to set the maximum size
    for a container's logs (#7434).

  - The --network option to the podman pod create command
    now allows pods to be configured to use slirp4netns
    networking, even when run as root (#6097).

  - The podman pod stop, podman pod pause, podman pod
    unpause, and podman pod kill commands now work on
    multiple containers in parallel and should be
    significantly faster.

  - The podman search command now supports a --list-tags
    option to list all available tags for a single image in
    a single repository.

  - The podman search command can now output JSON using the
    --format=json option.

  - The podman diff and podman mount commands now work with
    all containers in the storage library, including those
    not created by Podman. This allows them to be used with
    Buildah and CRI-O containers.

  - The podman container exists command now features a
    --external option to check if a container exists not
    just in Podman, but also in the storage library. This
    will allow Podman to identify Buildah and CRI-O
    containers.

  - The --tls-verify and --authfile options have been
    enabled for use with remote Podman.

  - The /etc/hosts file now includes the container's name
    and hostname (both pointing to localhost) when the
    container is run with --net=none (#8095).

  - The podman events command now supports filtering events
    based on the labels of the container they occurred on
    using the --filter label=key=value option.

  - The podman volume ls command now supports filtering
    volumes based on their labels using the --filter
    label=key=value option.

  - The --volume and --mount options to podman run and
    podman create now support two new mount propagation
    options, unbindable and runbindable.

  - The name and id filters for podman pod ps now match
    based on a regular expression, instead of requiring an
    exact match.

  - The podman pod ps command now supports a new filter
    status, that matches pods in a certain state.

  - Changes

  - The podman network rm --force command will now also
    remove pods that are using the network (#7791).

  - The podman volume rm, podman network rm, and podman pod
    rm commands now return exit code 1 if the object
    specified for removal does not exist, and exit code 2 if
    the object is in use and the --force option was not
    given.

  - If /dev/fuse is passed into Podman containers as a
    device, Podman will open it before starting the
    container to ensure that the kernel module is loaded on
    the host and the device is usable in the container.

  - Global Podman options that were not supported with
    remote operation have been removed from podman-remote
    (e.g. --cgroup-manager, --storage-driver).

  - Many errors have been changed to remove repetition and
    be more clear as to what has gone wrong.

  - The --storage option to podman rm is now enabled by
    default, with slightly changed semantics. If the given
    container does not exist in Podman but does exist in the
    storage library, it will be removed even without the
    --storage option. If the container exists in Podman it
    will be removed normally. The --storage option for
    podman rm is now deprecated and will be removed in a
    future release.

  - The --storage option to podman ps has been renamed to
    --external. An alias has been added so the old form of
    the option will continue to work.

  - Podman now delays the SIGTERM and SIGINT signals during
    container creation to ensure that Podman is not stopped
    midway through creating a container resulting in
    potential resource leakage (#7941).

  - The podman save command now strips signatures from
    images it is exporting, as the formats we export to do
    not support signatures (#7659).

  - A new Degraded state has been added to pods. Pods that
    have some, but not all, of their containers running are
    now considered to be Degraded instead of Running.

  - Podman will now print a warning when conflicting network
    options related to port forwarding (e.g. --publish and
    --net=host) are specified when creating a container.

  - The --restart on-failure and --rm options for containers
    no longer conflict. When both are specified, the
    container will be restarted if it exits with a non-zero
    error code, and removed if it exits cleanly (#7906).

  - Remote Podman will no longer use settings from the
    client's containers.conf; defaults will instead be
    provided by the server's containers.conf (#7657).

  - The podman network rm command now has a new alias,
    podman network remove (#8402).

  - Bugfixes

  - Fixed a bug where podman load on the remote client did
    not error when attempting to load a directory, which is
    not yet supported for remote use.

  - Fixed a bug where rootless Podman could hang when the
    newuidmap binary was not installed (#7776).

  - Fixed a bug where the --pull option to podman run,
    podman create, and podman build did not match Docker's
    behavior.

  - Fixed a bug where sysctl settings from the
    containers.conf configuration file were applied, even if
    the container did not join the namespace associated with
    a sysctl.

  - Fixed a bug where Podman would not return the text of
    errors encounted when trying to run a healthcheck for a
    container.

  - Fixed a bug where Podman was accidentally setting the
    containers environment variable in addition to the
    expected container environment variable.

  - Fixed a bug where rootless Podman using CNI networking
    did not properly clean up DNS entries for removed
    containers (#7789).

  - Fixed a bug where the podman untag --all command was not
    supported with remote Podman.

  - Fixed a bug where the podman system service command
    could time out even if active attach connections were
    present (#7826).

  - Fixed a bug where the podman system service command
    would sometimes never time out despite no active
    connections being present.

  - Fixed a bug where Podman's handling of capabilities,
    specifically inheritable, did not match Docker's.

  - Fixed a bug where podman run would fail if the image
    specified was a manifest list and had already been
    pulled (#7798).

  - Fixed a bug where Podman did not take search registries
    into account when looking up images locally (#6381).

  - Fixed a bug where the podman manifest inspect command
    would fail for images that had already been pulled
    (#7726).

  - Fixed a bug where rootless Podman would not add
    supplemental GIDs to containers when when a user, but
    not a group, was set via the --user option to podman
    create and podman run and sufficient GIDs were available
    to add the groups (#7782).

  - Fixed a bug where remote Podman commands did not
    properly handle cases where the user gave a name that
    could also be a short ID for a pod or container (#7837).

  - Fixed a bug where podman image prune could leave images
    ready to be pruned after podman image prune was run
    (#7872).

  - Fixed a bug where the podman logs command with the
    journald log driver would not read all available logs
    (#7476).

  - Fixed a bug where the --rm and --restart options to
    podman create and podman run did not conflict when a
    restart policy that is not on-failure was chosen
    (#7878).

  - Fixed a bug where the --format 'table (( .Field ))'
    option to numerous Podman commands ceased to function on
    Podman v2.0 and up.

  - Fixed a bug where pods did not properly share an SELinux
    label between their containers, resulting in containers
    being unable to see the processes of other containers
    when the pod shared a PID namespace (#7886).

  - Fixed a bug where the --namespace option to podman ps
    did not work with the remote client (#7903).

  - Fixed a bug where rootless Podman incorrectly calculated
    the number of UIDs available in the container if
    multiple different ranges of UIDs were specified.

  - Fixed a bug where the /etc/hosts file would not be
    correctly populated for containers in a user namespace
    (#7490).

  - Fixed a bug where the podman network create and podman
    network remove commands could race when run in parallel,
    with unpredictable results (#7807).

  - Fixed a bug where the -p option to podman run, podman
    create, and podman pod create would, when given only a
    single number (e.g. -p 80), assign the same port for
    both host and container, instead of generating a random
    host port (#7947).

  - Fixed a bug where Podman containers did not properly
    store the cgroup manager they were created with, causing
    them to stop functioning after the cgroup manager was
    changed in containers.conf or with the --cgroup-manager
    option (#7830).

  - Fixed a bug where the podman inspect command did not
    include information on the CNI networks a container was
    connected to if it was not running.

  - Fixed a bug where the podman attach command would not
    print a newline after detaching from the container
    (#7751).

  - Fixed a bug where the HOME environment variable was not
    set properly in containers when the --userns=keep-id
    option was set (#8004).

  - Fixed a bug where the podman container restore command
    could panic when the container in question was in a pod
    (#8026).

  - Fixed a bug where the output of the podman image trust
    show --raw command was not properly formatted.

  - Fixed a bug where the podman runlabel command could
    panic if a label to run was not given (#8038).

  - Fixed a bug where the podman run and podman start
    --attach commands would exit with an error when the user
    detached manually using the detach keys on remote Podman
    (#7979).

  - Fixed a bug where rootless CNI networking did not use
    the dnsname CNI plugin if it was not available on the
    host, despite it always being available in the container
    used for rootless networking (#8040).

  - Fixed a bug where Podman did not properly handle cases
    where an OCI runtime is specified by its full path, and
    could revert to using another OCI runtime with the same
    binary path that existed in the system $PATH on
    subsequent invocations.

  - Fixed a bug where the --net=host option to podman create
    and podman run would cause the /etc/hosts file to be
    incorrectly populated (#8054).

  - Fixed a bug where the podman inspect command did not
    include container network information when the container
    shared its network namespace (IE, joined a pod or
    another container's network namespace via
    --net=container:...) (#8073).

  - Fixed a bug where the podman ps command did not include
    information on all ports a container was publishing.

  - Fixed a bug where the podman build command incorrectly
    forwarded STDIN into build containers from RUN
    instructions.

  - Fixed a bug where the podman wait command's --interval
    option did not work when units were not specified for
    the duration (#8088).

  - Fixed a bug where the --detach-keys and --detach options
    could be passed to podman create despite having no
    effect (and not making sense in that context).

  - Fixed a bug where Podman could not start containers if
    running on a system without a /etc/resolv.conf file
    (which occurs on some WSL2 images) (#8089).

  - Fixed a bug where the --extract option to podman cp was
    nonfunctional.

  - Fixed a bug where the --cidfile option to podman run
    would, when the container was not run with --detach,
    only create the file after the container exited (#8091).

  - Fixed a bug where the podman images and podman images -a
    commands could panic and not list any images when
    certain improperly-formatted images were present in
    storage (#8148).

  - Fixed a bug where the podman events command could, when
    the journald events backend was in use, become
    nonfunctional when a badly-formatted event or a log
    message that container certain string was present in the
    journal (#8125).

  - Fixed a bug where remote Podman would, when using SSH
    transport, not authenticate to the server using hostkeys
    when connecting on a port other than 22 (#8139).

  - Fixed a bug where the podman attach command would not
    exit when containers stopped (#8154).

  - Fixed a bug where Podman did not properly clean paths
    before verifying them, resulting in Podman refusing to
    start if the root or temporary directories were
    specified with extra trailing / characters (#8160).

  - Fixed a bug where remote Podman did not support hashed
    hostnames in the known_hosts file on the host for
    establishing connections (#8159).

  - Fixed a bug where the podman image exists command would
    return non-zero (false) when multiple potential matches
    for the given name existed.

  - Fixed a bug where the podman manifest inspect command on
    images that are not manifest lists would error instead
    of inspecting the image (#8023).

  - Fixed a bug where the podman system service command
    would fail if the directory the Unix socket was to be
    created inside did not exist (#8184).

  - Fixed a bug where pods that shared the IPC namespace
    (which is done by default) did not share a /dev/shm
    filesystem between all containers in the pod (#8181).

  - Fixed a bug where filters passed to podman volume list
    were not inclusive (#6765).

  - Fixed a bug where the podman volume create command would
    fail when the volume's data directory already existed
    (as might occur when a volume was not completely
    removed) (#8253).

  - Fixed a bug where the podman run and podman create
    commands would deadlock when trying to create a
    container that mounted the same named volume at multiple
    locations (e.g. podman run -v testvol:/test1 -v
    testvol:/test2) (#8221).

  - Fixed a bug where the parsing of the --net option to
    podman build was incorrect (#8322).

  - Fixed a bug where the podman build command would print
    the ID of the built image twice when using remote Podman
    (#8332).

  - Fixed a bug where the podman stats command did not show
    memory limits for containers (#8265).

  - Fixed a bug where the podman pod inspect command printed
    the static MAC address of the pod in a
    non-human-readable format (#8386).

  - Fixed a bug where the --tls-verify option of the podman
    play kube command had its logic inverted (false would
    enforce the use of TLS, true would disable it).

  - Fixed a bug where the podman network rm command would
    error when trying to remove macvlan networks and
    rootless CNI networks (#8491).

  - Fixed a bug where Podman was not setting sane defaults
    for missing XDG_ environment variables.

  - Fixed a bug where remote Podman would check if volume
    paths to be mounted in the container existed on the
    host, not the server (#8473).

  - Fixed a bug where the podman manifest create and podman
    manifest add commands on local images would drop any
    images in the manifest not pulled by the host.

  - Fixed a bug where networks made by podman network create
    did not include the tuning plugin, and as such did not
    support setting custom MAC addresses (#8385).

  - Fixed a bug where container healthchecks did not use
    $PATH when searching for the Podman executable to run
    the healthcheck.

  - Fixed a bug where the --ip-range option to podman
    network create did not properly handle non-classful
    subnets when calculating the last usable IP for DHCP
    assignment (#8448).

  - Fixed a bug where the podman container ps alias for
    podman ps was missing (#8445).

  - API

  - The Compat Create endpoint for Container has received a
    major refactor to share more code with the Libpod Create
    endpoint, and should be significantly more stable.

  - A Compat endpoint for exporting multiple images at once,
    GET /images/get, has been added (#7950).

  - The Compat Network Connect and Network Disconnect
    endpoints have been added.

  - Endpoints that deal with image registries now support a
    X-Registry-Config header to specify registry
    authentication configuration.

  - The Compat Create endpoint for images now properly
    supports specifying images by digest.

  - The Libpod Build endpoint for images now supports an
    httpproxy query parameter which, if set to true, will
    forward the server's HTTP proxy settings into the build
    container for RUN instructions.

  - The Libpod Untag endpoint for images will now remove all
    tags for the given image if no repository and tag are
    specified for removal.

  - Fixed a bug where the Ping endpoint misspelled a header
    name (Libpod-Buildha-Version instead of
    Libpod-Buildah-Version).

  - Fixed a bug where the Ping endpoint sent an extra
    newline at the end of its response where Docker did not.

  - Fixed a bug where the Compat Logs endpoint for
    containers did not send a newline character after each
    log line.

  - Fixed a bug where the Compat Logs endpoint for
    containers would mangle line endings to change newline
    characters to add a preceding carriage return (#7942).

  - Fixed a bug where the Compat Inspect endpoint for
    Containers did not properly list the container's stop
    signal (#7917).

  - Fixed a bug where the Compat Inspect endpoint for
    Containers formatted the container's create time
    incorrectly (#7860).

  - Fixed a bug where the Compat Inspect endpoint for
    Containers did not include the container's Path, Args,
    and Restart Count.

  - Fixed a bug where the Compat Inspect endpoint for
    Containers prefixed added and dropped capabilities with
    CAP_ (Docker does not do so).

  - Fixed a bug where the Compat Info endpoint for the
    Engine did not include configured registries.

  - Fixed a bug where the server could panic if a client
    closed a connection midway through an image pull
    (#7896).

  - Fixed a bug where the Compat Create endpoint for volumes
    returned an error when a volume with the same name
    already existed, instead of succeeding with a 201 code
    (#7740).

  - Fixed a bug where a client disconnecting from the Libpod
    or Compat events endpoints could result in the server
    using 100% CPU (#7946).

  - Fixed a bug where the 'no such image' error message sent
    by the Compat Inspect endpoint for Images returned a 404
    status code with an error that was improperly formatted
    for Docker compatibility.

  - Fixed a bug where the Compat Create endpoint for
    networks did not properly set a default for the driver
    parameter if it was not provided by the client.

  - Fixed a bug where the Compat Inspect endpoint for images
    did not populate the RootFS field of the response.

  - Fixed a bug where the Compat Inspect endpoint for images
    would omit the ParentId field if the image had no
    parent, and the Created field if the image did not have
    a creation time.

  - Fixed a bug where the Compat Remove endpoint for
    Networks did not support the Force query parameter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165184"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected buildah / libcontainers-common / podman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcontainers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman-cni-config");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"buildah-1.19.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcontainers-common-20210112-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"podman-2.2.1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"podman-cni-config-2.2.1-lp152.4.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "buildah / libcontainers-common / podman / podman-cni-config");
}
