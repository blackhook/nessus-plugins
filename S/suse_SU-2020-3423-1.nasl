#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3423-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143725);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2019-10214", "CVE-2020-10696");

  script_name(english:"SUSE SLES15 Security Update : buildah (SUSE-SU-2020:3423-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for buildah fixes the following issues :

buildah was updated to v1.17.0 (bsc#1165184) :

Handle cases where other tools mount/unmount containers

overlay.MountReadOnly: support RO overlay mounts

overlay: use fusermount for rootless umounts

overlay: fix umount

Switch default log level of Buildah to Warn. Users need to see these
messages

Drop error messages about OCI/Docker format to Warning level

build(deps): bump github.com/containers/common from 0.26.0 to 0.26.2

tests/testreport: adjust for API break in storage v1.23.6

build(deps): bump github.com/containers/storage from 1.23.5 to 1.23.7

build(deps): bump github.com/fsouza/go-dockerclient from 1.6.5 to
1.6.6

copier: put: ignore Typeflag='g'

Use curl to get repo file (fix #2714)

build(deps): bump github.com/containers/common from 0.25.0 to 0.26.0

build(deps): bump github.com/spf13/cobra from 1.0.0 to 1.1.1

Remove docs that refer to bors, since we're not using it

Buildah bud should not use stdin by default

bump containerd, docker, and golang.org/x/sys

Makefile: cross: remove windows.386 target

copier.copierHandlerPut: don't check length when there are errors

Stop excessive wrapping

CI: require that conformance tests pass

bump(github.com/openshift/imagebuilder) to v1.1.8

Skip tlsVerify insecure BUILD_REGISTRY_SOURCES

Fix build path wrong containers/podman#7993

refactor pullpolicy to avoid deps

build(deps): bump github.com/containers/common from 0.24.0 to 0.25.0

CI: run gating tasks with a lot more memory

ADD and COPY: descend into excluded directories, sometimes

copier: add more context to a couple of error messages

copier: check an error earlier

copier: log stderr output as debug on success

Update nix pin with make nixpkgs

Set directory ownership when copied with ID mapping

build(deps): bump github.com/sirupsen/logrus from 1.6.0 to 1.7.0

build(deps): bump github.com/containers/common from 0.23.0 to 0.24.0

Cirrus: Remove bors artifacts

Sort build flag definitions alphabetically

ADD: only expand archives at the right time

Remove configuration for bors

Shell Completion for podman build flags

Bump c/common to v0.24.0

New CI check: xref --help vs man pages

CI: re-enable several linters

Move --userns-uid-map/--userns-gid-map description into buildah man
page

add: preserve ownerships and permissions on ADDed archives

Makefile: tweak the cross-compile target

Bump containers/common to v0.23.0

chroot: create bind mount targets 0755 instead of 0700

Change call to Split() to safer SplitN()

chroot: fix handling of errno seccomp rules

build(deps): bump github.com/containers/image/v5 from 5.5.2 to 5.6.0

Add In Progress section to contributing

integration tests: make sure tests run in ${topdir}/tests

Run(): ignore containers.conf's environment configuration

Warn when setting healthcheck in OCI format

Cirrus: Skip git-validate on branches

tools: update git-validation to the latest commit

tools: update golangci-lint to v1.18.0

Add a few tests of push command

Add(): fix handling of relative paths with no ContextDir

build(deps): bump github.com/containers/common from 0.21.0 to 0.22.0

Lint: Use same linters as podman

Validate: reference HEAD

Fix buildah mount to display container names not ids

Update nix pin with make nixpkgs

Add missing --format option in buildah from man page

Fix up code based on codespell

build(deps): bump github.com/openshift/imagebuilder from 1.1.6 to
1.1.7

build(deps): bump github.com/containers/storage from 1.23.4 to 1.23.5

Improve buildah completions

Cirrus: Fix validate commit epoch

Fix bash completion of manifest flags

Uniform some man pages

Update Buildah Tutorial to address BZ1867426

Update bash completion of manifest add sub command

copier.Get(): hard link targets shouldn't be relative paths

build(deps): bump github.com/onsi/gomega from 1.10.1 to 1.10.2

Pass timestamp down to history lines

Timestamp gets updated everytime you inspect an image

bud.bats: use absolute paths in newly-added tests

contrib/cirrus/lib.sh: don't use CN for the hostname

tests: Add some tests

Update manifest add man page

Extend flags of manifest add

build(deps): bump github.com/containers/storage from 1.23.3 to 1.23.4

build(deps): bump github.com/onsi/ginkgo from 1.14.0 to 1.14.1

CI: expand cross-compile checks

Update to v1.16.2 :

fix build on 32bit arches

containerImageRef.NewImageSource(): don't always force timestamps

Add fuse module warning to image readme

Heed our retry delay option values when retrying commit/pull/push

Switch to containers/common for seccomp

Use --timestamp rather then --omit-timestamp

docs: remove outdated notice

docs: remove outdated notice

build-using-dockerfile: add a hidden --log-rusage flag

build(deps): bump github.com/containers/image/v5 from 5.5.1 to 5.5.2

Discard ReportWriter if user sets options.Quiet

build(deps): bump github.com/containers/common from 0.19.0 to 0.20.3

Fix ownership of content copied using COPY --from

newTarDigester: zero out timestamps in tar headers

Update nix pin with `make nixpkgs`

bud.bats: correct .dockerignore integration tests

Use pipes for copying

run: include stdout in error message

run: use the correct error for errors.Wrapf

copier: un-export internal types

copier: add Mkdir()

in_podman: don't get tripped up by $CIRRUS_CHANGE_TITLE

docs/buildah-commit.md: tweak some wording, add a --rm example

imagebuildah: don&acirc;&#128;&#153;t blank out destination names when
COPYing

Replace retry functions with common/pkg/retry

StageExecutor.historyMatches: compare timestamps using .Equal

Update vendor of containers/common

Fix errors found in coverity scan

Change namespace handling flags to better match podman commands

conformance testing: ignore buildah.BuilderIdentityAnnotation labels

Vendor in containers/storage v1.23.0

Add buildah.IsContainer interface

Avoid feeding run_buildah to pipe

fix(buildahimage): add xz dependency in buildah image

Bump github.com/containers/common from 0.15.2 to 0.18.0

Howto for rootless image building from OpenShift

Add --omit-timestamp flag to buildah bud

Update nix pin with `make nixpkgs`

Shutdown storage on failures

Handle COPY --from when an argument is used

Bump github.com/seccomp/containers-golang from 0.5.0 to 0.6.0

Cirrus: Use newly built VM images

Bump github.com/opencontainers/runc from 1.0.0-rc91 to 1.0.0-rc92

Enhance the .dockerignore man pages

conformance: add a test for COPY from subdirectory

fix bug manifest inspct

Add documentation for .dockerignore

Add BuilderIdentityAnnotation to identify buildah version

DOC: Add quay.io/containers/buildah image to README.md

Update buildahimages readme

fix spelling mistake in 'info' command result display

Don't bind /etc/host and /etc/resolv.conf if network is not present

blobcache: avoid an unnecessary NewImage()

Build static binary with `buildGoModule`

copier: split StripSetidBits into
StripSetuidBit/StripSetgidBit/StripStickyBit

tarFilterer: handle multiple archives

Fix a race we hit during conformance tests

Rework conformance testing

Update 02-registries-repositories.md

test-unit: invoke cmd/buildah tests with --flags

parse: fix a type mismatch in a test

Fix compilation of tests/testreport/testreport

build.sh: log the version of Go that we're using

test-unit: increase the test timeout to 40/45 minutes

Add the 'copier' package

Fix & add notes regarding problematic language in codebase

Add dependency on github.com/stretchr/testify/require

CompositeDigester: add the ability to filter tar streams

BATS tests: make more robust

vendor golang.org/x/text@v0.3.3

Switch golang 1.12 to golang 1.13

imagebuildah: wait for stages that might not have even started yet

chroot, run: not fail on bind mounts from /sys

chroot: do not use setgroups if it is blocked

Set engine env from containers.conf

imagebuildah: return the right stage's image as the 'final' image

Fix a help string

Deduplicate environment variables

switch containers/libpod to containers/podman

Bump github.com/containers/ocicrypt from 1.0.2 to 1.0.3

Bump github.com/opencontainers/selinux from 1.5.2 to 1.6.0

Mask out /sys/dev to prevent information leak

linux: skip errors from the runtime kill

Mask over the /sys/fs/selinux in mask branch

Add VFS additional image store to container

tests: add auth tests

Allow 'readonly' as alias to 'ro' in mount options

Ignore OS X specific consistency mount option

Bump github.com/onsi/ginkgo from 1.13.0 to 1.14.0

Bump github.com/containers/common from 0.14.0 to 0.15.2

Rootless Buildah should default to IsolationOCIRootless

imagebuildah: fix inheriting multi-stage builds

Make imagebuildah.BuildOptions.Architecture/OS optional

Make imagebuildah.BuildOptions.Jobs optional

Resolve a possible race in imagebuildah.Executor.startStage()

Switch scripts to use containers.conf

Bump openshift/imagebuilder to v1.1.6

Bump go.etcd.io/bbolt from 1.3.4 to 1.3.5

buildah, bud: support --jobs=N for parallel execution

executor: refactor build code inside new function

Add bud regression tests

Cirrus: Fix missing htpasswd in registry img

docs: clarify the 'triples' format

CHANGELOG.md: Fix markdown formatting

Add nix derivation for static builds

Bump to v1.16.0-dev

Update to v1.15.1

Mask over the /sys/fs/selinux in mask branch

chroot: do not use setgroups if it is blocked

chroot, run: not fail on bind mounts from /sys

Allow 'readonly' as alias to 'ro' in mount options

Add VFS additional image store to container

vendor golang.org/x/text@v0.3.3

Make imagebuildah.BuildOptions.Architecture/OS optional

Update to v1.15.0 :

Add CVE-2020-10696 to CHANGELOG.md and changelog.txt

fix lighttpd example

remove dependency on openshift struct

Warn on unset build arguments

vendor: update seccomp/containers-golang to v0.4.1

Updated docs

clean up comments

update exit code for tests

Implement commit for encryption

implementation of encrypt/decrypt push/pull/bud/from

fix resolve docker image name as transport

Add preliminary profiling support to the CLI

Evaluate symlinks in build context directory

fix error info about get signatures for containerImageSource

Add Security Policy

Cirrus: Fixes from review feedback

imagebuildah: stages shouldn't count as their base images

Update containers/common v0.10.0

Add registry to buildahimage Dockerfiles

Cirrus: Use pre-installed VM packages + F32

Cirrus: Re-enable all distro versions

Cirrus: Update to F31 + Use cache images

golangci-lint: Disable gosimple

Lower number of golangci-lint threads

Fix permissions on containers.conf

Don't force tests to use runc

Return exit code from failed containers

cgroup_manager should be under [engine]

Use c/common/pkg/auth in login/logout

Cirrus: Temporarily disable Ubuntu 19 testing

Add containers.conf to stablebyhand build

Update gitignore to exclude test Dockerfiles

Remove warning for systemd inside of container

Update to v1.14.6 :

Make image history work correctly with new args handling

Don't add args to the RUN environment from the Builder

Update to v1.14.5 :

Revert FIPS mode change

Update to v1.14.4 :

Update unshare man page to fix script example

Fix compilation errors on non linux platforms

Preserve volume uid and gid through subsequent commands

Fix potential CVE in tarfile w/ symlink

Fix .dockerignore with globs and ! commands

Update to v1.14.2 :

Search for local runtime per values in containers.conf

Set correct ownership on working directory

Improve remote manifest retrieval

Correct a couple of incorrect format specifiers

manifest push --format: force an image type, not a list type

run: adjust the order in which elements are added to $

getDateAndDigestAndSize(): handle creation time not being set

Make the commit id clear like Docker

Show error on copied file above context directory in build

pull/from/commit/push: retry on most failures

Repair buildah so it can use containers.conf on the server side

Fixing formatting & build instructions

Fix XDG_RUNTIME_DIR for authfile

Show validation command-line

Update to v1.14.0 :

getDateAndDigestAndSize(): use manifest.Digest

Touch up os/arch doc

chroot: handle slightly broken seccomp defaults

buildahimage: specify fuse-overlayfs mount options

parse: don't complain about not being able to rename something to
itself

Fix build for 32bit platforms

Allow users to set OS and architecture on bud

Fix COPY in containerfile with envvar

Add --sign-by to bud/commit/push, --remove-signatures for pull/push

Add support for containers.conf

manifest push: add --format option

Update to v1.13.1 :

copyFileWithTar: close source files at the right time

copy: don't digest files that we ignore

Check for .dockerignore specifically

Don't setup excludes, if their is only one pattern to match

set HOME env to /root on chroot-isolation by default

docs: fix references to containers-*.5

fix bug Add check .dockerignore COPY file

buildah bud --volume: run from tmpdir, not source dir

Fix imageNamePrefix to give consistent names in buildah-from

cpp: use -traditional and -undef flags

discard outputs coming from onbuild command on buildah-from --quiet

make --format columnizing consistent with buildah images

Fix option handling for volumes in build

Rework overlay pkg for use with libpod

Fix buildahimage builds for buildah

Add support for FIPS-Mode backends

Set the TMPDIR for pulling/pushing image to $TMPDIR

Update to v1.12.0 :

Allow ADD to use http src

imgtype: reset storage opts if driver overridden

Start using containers/common

overlay.bats typo: fuse-overlays should be fuse-overlayfs

chroot: Unmount with MNT_DETACH instead of UnmountMountpoints()

bind: don't complain about missing mountpoints

imgtype: check earlier for expected manifest type

Add history names support

Update to v1.11.6 :

Handle missing equal sign in --from and --chown flags for COPY/ADD

bud COPY does not download URL

Fix .dockerignore exclude regression

commit(docker): always set ContainerID and ContainerConfig

Touch up commit man page image parameter

Add builder identity annotations.

Update to v1.11.5 :

buildah: add 'manifest' command

pkg/supplemented: add a package for grouping images together

pkg/manifests: add a manifest list build/manipulation API

Update for ErrUnauthorizedForCredentials API change in
containers/image

Update for manifest-lists API changes in containers/image

version: also note the version of containers/image

Move to containers/image v5.0.0

Enable --device directory as src device

Add clarification to the Tutorial for new users

Silence 'using cache' to ensure -q is fully quiet

Move runtime flag to bud from common

Commit: check for storage.ErrImageUnknown using errors.Cause()

Fix crash when invalid COPY --from flag is specified.

Update to v1.11.4 :

buildah: add a 'manifest' command

pkg/manifests: add a manifest list build/manipulation API

Update for ErrUnauthorizedForCredentials API change in
containers/image

Update for manifest-lists API changes in containers/image

Move to containers/image v5.0.0

Enable --device directory as src device

Add clarification to the Tutorial for new users

Silence 'using cache' to ensure -q is fully quiet

Move runtime flag to bud from common

Commit: check for storage.ErrImageUnknown using errors.Cause()

Fix crash when invalid COPY --from flag is specified.

Update to v1.11.3 :

Add cgroups2

Add support for retrieving context from stdin '-'

Added tutorial on how to include Buildah as library

Fix --build-args handling

Print build 'STEP' line to stdout, not stderr

Use Containerfile by default

Update to v1.11.2 :

Add some cleanup code

Move devices code to unit specific directory.

Update to v1.11.1 :

Add --devices flag to bud and from

Add support for /run/.containerenv

Allow mounts.conf entries for equal source and destination paths

Fix label and annotation for 1-line Dockerfiles

Preserve file and directory mount permissions

Replace --debug=false with --log-level=error

Set TMPDIR to /var/tmp by default

Truncate output of too long image names

Ignore EmptyLayer if Squash is set

Update to v1.11.0 :

Add --digestfile and Re-add push statement as debug

Add --log-level command line option and deprecate --debug

Add security-related volume options to validator

Allow buildah bud to be called without arguments

Allow to override build date with SOURCE_DATE_EPOCH

Correctly detect ExitError values from Run()

Disable empty logrus timestamps to reduce logger noise

Fix directory pull image names

Fix handling of /dev/null masked devices

Fix possible runtime panic on bud

Update bud/from help to contain indicator for --dns=none

Update documentation about bud

Update shebangs to take env into consideration

Use content digests in ADD/COPY history entries

add support for cgroupsV2

add: add a DryRun flag to AddAndCopyOptions

add: handle hard links when copying with .dockerignore

add: teach copyFileWithTar() about symlinks and directories

imagebuilder: fix detection of referenced stage roots

pull/commit/push: pay attention to $BUILD_REGISTRY_SOURCES

run_linux: fix mounting /sys in a userns

Update to v1.10.1 :

Add automatic apparmor tag discovery

Add overlayfs to fuse-overlayfs tip

Bug fix for volume minus syntax

Bump container/storage v1.13.1 and containers/image v3.0.1

Bump containers/image to v3.0.2 to fix keyring issue

Fix bug whereby --get-login has no effect

Bump github.com/containernetworking/cni to v0.7.1

Add appamor-pattern requirement

Update build process to match the latest repository architecture

Update to v1.10.0

vendor github.com/containers/image@v3.0.0

Remove GO111MODULE in favor of -mod=vendor

Vendor in containers/storage v1.12.16

Add '-' minus syntax for removal of config values

tests: enable overlay tests for rootless

rootless, overlay: use fuse-overlayfs

vendor github.com/containers/image@v2.0.1

Added '-' syntax to remove volume config option

delete successfully pushed message

Add golint linter and apply fixes

vendor github.com/containers/storage@v1.12.15

Change wait to sleep in buildahimage readme

Handle ReadOnly images when deleting images

Add support for listing read/only images

from/import: record the base image's digest, if it has one

Fix CNI version retrieval to not require network connection

Add misspell linter and apply fixes

Add goimports linter and apply fixes

Add stylecheck linter and apply fixes

Add unconvert linter and apply fixes

image: make sure we don't try to use zstd compression

run.bats: skip the 'z' flag when testing --mount

Update to runc v1.0.0-rc8

Update to match updated runtime-tools API

bump github.com/opencontainers/runtime-tools to v0.9.0

Build e2e tests using the proper build tags

Add unparam linter and apply fixes

Run: correct a typo in the --cap-add help text

unshare: add a --mount flag

fix push check image name is not empty

add: fix slow copy with no excludes

Add errcheck linter and fix missing error check

Improve tests/tools/Makefile parallelism and abstraction

Fix response body not closed resource leak

Switch to golangci-lint

Add gomod instructions and mailing list links

On Masked path, check if /dev/null already mounted before mounting

Update to containers/storage v1.12.13

Refactor code in package imagebuildah

Add rootless podman with NFS issue in documentation

Add --mount for buildah run

import method ValidateVolumeOpts from libpod

Fix typo

Makefile: set GO111MODULE=off

rootless: add the built-in slirp DNS server

Update docker/libnetwork to get rid of outdated sctp package

Update buildah-login.md

migrate to go modules

install.md: mention go modules

tests/tools: go module for test binaries

fix --volume splits comma delimited option

Add bud test for RUN with a priv'd command

vendor logrus v1.4.2

pkg/cli: panic when flags can't be hidden

pkg/unshare: check all errors

pull: check error during report write

run_linux.go: ignore unchecked errors

conformance test: catch copy error

chroot/run_test.go: export funcs to actually be executed

tests/imgtype: ignore error when shutting down the store

testreport: check json error

bind/util.go: remove unused func

rm chroot/util.go

imagebuildah: remove unused dedupeStringSlice

StageExecutor: EnsureContainerPath: catch error from SecureJoin()

imagebuildah/build.go: return instead of branching

rmi: avoid redundant branching

conformance tests: nilness: allocate map

imagebuildah/build.go: avoid redundant filepath.Join()

imagebuildah/build.go: avoid redundant os.Stat()

imagebuildah: omit comparison to bool

fix 'ineffectual assignment' lint errors

docker: ignore 'repeats json tag' lint error

pkg/unshare: use ... instead of iterating a slice

conformance: bud test: use raw strings for regexes

conformance suite: remove unused func/var

buildah test suite: remove unused vars/funcs

testreport: fix golangci-lint errors

util: remove redundant return statement

chroot: only log clean-up errors

images_test: ignore golangci-lint error

blobcache: log error when draining the pipe

imagebuildah: check errors in deferred calls

chroot: fix error handling in deferred funcs

cmd: check all errors

chroot/run_test.go: check errors

chroot/run.go: check errors in deferred calls

imagebuildah.Executor: remove unused onbuild field

docker/types.go: remove unused struct fields

util: use strings.ContainsRune instead of index check

Cirrus: Initial implementation

buildah-run: fix-out-of-range panic (2)

Update containers/image to v2.0.0

run: fix hang with run and --isolation=chroot

run: fix hang when using run

chroot: drop unused function call

remove --> before imgageID on build

Always close stdin pipe

Write deny to setgroups when doing single user mapping

Avoid including linux/memfd.h

Add a test for the symlink pointing to a directory

Add missing continue

Fix the handling of symlinks to absolute paths

Only set default network sysctls if not rootless

Support --dns=none like podman

fix bug --cpu-shares parsing typo

Fix validate complaint

Update vendor on containers/storage to v1.12.10

Create directory paths for COPY thereby ensuring correct perms

imagebuildah: use a stable sort for comparing build args

imagebuildah: tighten up cache checking

bud.bats: add a test verying the order of --build-args

add -t to podman run

imagebuildah: simplify screening by top layers

imagebuildah: handle ID mappings for COPY --from

imagebuildah: apply additionalTags ourselves

bud.bats: test additional tags with cached images

bud.bats: add a test for WORKDIR and COPY with absolute destinations

Cleanup Overlay Mounts content

Add support for file secret mounts

Add ability to skip secrets in mounts file

allow 32bit builds

fix tutorial instructions

imagebuilder: pass the right contextDir to Add()

add: use fileutils.PatternMatcher for .dockerignore

bud.bats: add another .dockerignore test

unshare: fallback to single usermapping

addHelperSymlink: clear the destination on os.IsExist errors

bud.bats: test replacing symbolic links

imagebuildah: fix handling of destinations that end with '/'

bud.bats: test COPY with a final '/' in the destination

linux: add check for sysctl before using it

unshare: set _CONTAINERS_ROOTLESS_GID

Rework buildahimamges

build context: support https git repos

Add a test for ENV special chars behaviour

Check in new Dockerfiles

Apply custom SHELL during build time

config: expand variables only at the command line

SetEnv: we only need to expand v once

Add default /root if empty on chroot iso

Add support for Overlay volumes into the container.

Export buildah validate volume functions so it can share code with
libpod

Bump baseline test to F30

Fix rootless handling of /dev/shm size

Avoid fmt.Printf() in the library

imagebuildah: tighten cache checking back up

Handle WORKDIR with dangling target

Default Authfile to proper path

Make buildah run --isolation follow BUILDAH_ISOLATION environment

Vendor in latest containers/storage and containers/image

getParent/getChildren: handle layerless images

imagebuildah: recognize cache images for layerless images

bud.bats: test scratch images with --layers caching

Get CHANGELOG.md updates

Add some symlinks to test our .dockerignore logic

imagebuildah: addHelper: handle symbolic links

commit/push: use an everything-allowed policy

Correct manpage formatting in files section

Remove must be root statement from buildah doc

Change image names to stable, testing and upstream

Don't create directory on container

Replace kubernetes/pause in tests with k8s.gcr.io/pause

imagebuildah: don't remove intermediate images if we need them

Rework buildahimagegit to buildahimageupstream

Fix Transient Mounts

Handle WORKDIRs that are symlinks

allow podman to build a client for windows

Touch up 1.9-dev to 1.9.0-dev

Resolve symlink when checking container path

commit: commit on every instruction, but not always with layers

CommitOptions: drop the unused OnBuild field

makeImageRef: pass in the whole CommitOptions structure

cmd: API cleanup: stores before images

run: check if SELinux is enabled

Fix buildahimages Dockerfiles to include support for additionalimages
mounted from host.

Detect changes in rootdir

Fix typo in buildah-pull(1)

Vendor in latest containers/storage

Keep track of any build-args used during buildah bud --layers

commit: always set a parent ID

imagebuildah: rework unused-argument detection

fix bug dest path when COPY .dockerignore

Move Host IDMAppings code from util to unshare

Add BUILDAH_ISOLATION rootless back

Travis CI: fail fast, upon error in any step

imagebuildah: only commit images for intermediate stages if we have to

Use errors.Cause() when checking for IsNotExist errors

auto pass http_proxy to container

imagebuildah: don't leak image structs

Add Dockerfiles for buildahimages

Bump to Replace golang 1.10 with 1.12

add --dns* flags to buildah bud

Add hack/build_speed.sh test speeds on building container images

Create buildahimage Dockerfile for Quay

rename 'is' to 'expect_output'

squash.bats: test squashing in multi-layered builds

bud.bats: test COPY --from in a Dockerfile while using the cache

commit: make target image names optional

Fix bud-args to allow comma separation

oops, missed some tests in commit.bats

new helper: expect_line_count

New tests for #1467 (string slices in cmdline opts)

Workarounds for dealing with travis; review feedback

BATS tests - extensive but minor cleanup

imagebuildah: defer pulling images for COPY --from

imagebuildah: centralize COMMIT and image ID output

Travis: do not use traviswait

imagebuildah: only initialize imagebuilder configuration once per
stage

Make cleaner error on Dockerfile build errors

unshare: move to pkg/

unshare: move some code from cmd/buildah/unshare

Fix handling of Slices versus Arrays

imagebuildah: reorganize stage and per-stage logic

imagebuildah: add empty layers for instructions

Add missing step in installing into Ubuntu

fix bug in .dockerignore support

imagebuildah: deduplicate prepended 'FROM' instructions

Touch up intro

commit: set created-by to the shell if it isn't set

commit: check that we always set a 'created-by'

docs/buildah.md: add 'containers-' prefixes under 'SEE ALSO'

Update to v1.7.2

Updates vendored containers/storage to latest version

rootless: by default use the host network namespace

Full changelog:
https://github.com/containers/buildah/releases/tag/v1.6

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1167864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/buildah/releases/tag/v1.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10214/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10696/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203423-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc11c168"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Containers 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP2-2020-3423=1

SUSE Linux Enterprise Module for Containers 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP1-2020-3423=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"buildah-1.17.0-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"buildah-1.17.0-3.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "buildah");
}
