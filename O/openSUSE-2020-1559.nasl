#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1559.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141077);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/05");

  script_cve_id("CVE-2020-1726");

  script_name(english:"openSUSE Security Update : conmon / fuse-overlayfs / libcontainers-common / etc (openSUSE-2020-1559)");
  script_summary(english:"Check for the openSUSE-2020-1559 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for conmon, fuse-overlayfs, libcontainers-common, podman
fixes the following issues :

podman was updated to v2.0.6 (bsc#1175821)

  - install missing systemd units for the new Rest API
    (bsc#1175957) and a few man-pages that where missing
    before

  - Drop varlink API related bits (in favor of the new API)

  - fix install location for zsh completions

  - Fixed a bug where running systemd in a container on a
    cgroups v1 system would fail.

  - Fixed a bug where /etc/passwd could be re-created every
    time a container is restarted if the container's
    /etc/passwd did not contain an entry for the user the
    container was started as.

  - Fixed a bug where containers without an /etc/passwd file
    specifying a non-root user would not start.

  - Fixed a bug where the --remote flag would sometimes not
    make remote connections and would instead attempt to run
    Podman locally.

Update to v2.0.6 :

  - Features

  - Rootless Podman will now add an entry to /etc/passwd for
    the user who ran Podman if run with --userns=keep-id.

  - The podman system connection command has been reworked
    to support multiple connections, and reenabled for use!

  - Podman now has a new global flag, --connection, to
    specify a connection to a remote Podman API instance.

  - Changes

  - Podman's automatic systemd integration (activated by the
    --systemd=true flag, set by default) will now activate
    for containers using /usr/local/sbin/init as their
    command, instead of just /usr/sbin/init and /sbin/init
    (and any path ending in systemd).

  - Seccomp profiles specified by the --security-opt
    seccomp=... flag to podman create and podman run will
    now be honored even if the container was created using
    --privileged.

  - Bugfixes

  - Fixed a bug where the podman play kube would not honor
    the hostIP field for port forwarding (#5964).

  - Fixed a bug where the podman generate systemd command
    would panic on an invalid restart policy being specified
    (#7271).

  - Fixed a bug where the podman images command could take a
    very long time (several minutes) to complete when a
    large number of images were present.

  - Fixed a bug where the podman logs command with the
    --tail flag would not work properly when a large amount
    of output would be printed
    ((#7230)[https://github.com//issues/7230]).

  - Fixed a bug where the podman exec command with remote
    Podman would not return a non-zero exit code when the
    exec session failed to start (e.g. invoking a
    non-existent command) (#6893).

  - Fixed a bug where the podman load command with remote
    Podman would did not honor user-specified tags (#7124).

  - Fixed a bug where the podman system service command,
    when run as a non-root user by Systemd, did not properly
    handle the Podman pause process and would not restart
    properly as a result (#7180).

  - Fixed a bug where the --publish flag to podman create,
    podman run, and podman pod create did not properly
    handle a host IP of 0.0.0.0 (attempting to bind to
    literal 0.0.0.0, instead of all IPs on the system)
    (#7104).

  - Fixed a bug where the podman start --attach command
    would not print the container's exit code when the
    command exited due to the container exiting.

  - Fixed a bug where the podman rm command with remote
    Podman would not remove volumes, even if the --volumes
    flag was specified (#7128).

  - Fixed a bug where the podman run command with remote
    Podman and the --rm flag could exit before the container
    was fully removed.

  - Fixed a bug where the --pod new:... flag to podman run
    and podman create would create a pod that did not share
    any namespaces.

  - Fixed a bug where the --preserve-fds flag to podman run
    and podman exec could close the wrong file descriptors
    while trying to close user-provided descriptors after
    passing them into the container.

  - Fixed a bug where default environment variables ($PATH
    and $TERM) were not set in containers when not provided
    by the image.

  - Fixed a bug where pod infra containers were not properly
    unmounted after exiting.

  - Fixed a bug where networks created with podman network
    create with an IPv6 subnet did not properly set an IPv6
    default route.

  - Fixed a bug where the podman save command would not work
    properly when its output was piped to another command
    (#7017).

  - Fixed a bug where containers using a systemd init on a
    cgroups v1 system could leak mounts under
    /sys/fs/cgroup/systemd to the host.

  - Fixed a bug where podman build would not generate an
    event on completion (#7022).

  - Fixed a bug where the podman history command with remote
    Podman printed incorrect creation times for layers
    (#7122).

  - Fixed a bug where Podman would not create working
    directories specified by the container image if they did
    not exist.

  - Fixed a bug where Podman did not clear CMD from the
    container image if the user overrode ENTRYPOINT (#7115).

  - Fixed a bug where error parsing image names were not
    fully reported (part of the error message containing the
    exact issue was dropped).

  - Fixed a bug where the podman images command with remote
    Podman did not support printing image tags in Go
    templates supplied to the --format flag (#7123).

  - Fixed a bug where the podman rmi --force command would
    not attempt to unmount containers it was removing, which
    could cause a failure to remove the image.

  - Fixed a bug where the podman generate systemd --new
    command could incorrectly quote arguments to Podman that
    contained whitespace, leading to nonfunctional unit
    files (#7285).

  - Fixed a bug where the podman version command did not
    properly include build time and Git commit.

  - Fixed a bug where running systemd in a Podman container
    on a system that did not use the systemd cgroup manager
    would fail (#6734).

  - Fixed a bug where capabilities from --cap-add were not
    properly added when a container was started as a
    non-root user via --user.

  - Fixed a bug where Pod infra containers were not properly
    cleaned up when they stopped, causing networking issues
    (#7103).

  - API

  - Fixed a bug where the libpod and compat Build endpoints
    did not accept the application/tar content type (instead
    only accepting application/x-tar) (#7185).

  - Fixed a bug where the libpod Exists endpoint would
    attempt to write a second header in some error
    conditions (#7197).

  - Fixed a bug where compat and libpod Network Inspect and
    Network Remove endpoints would return a 500 instead of
    404 when the requested network was not found.

  - Added a versioned _ping endpoint (e.g.
    http://localhost/v1.40/_ping).

  - Fixed a bug where containers started through a
    systemd-managed instance of the REST API would be shut
    down when podman system service shut down due to its
    idle timeout (#7294).

  - Added stronger parameter verification for the libpod
    Network Create endpoint to ensure subnet mask is a valid
    value.

  - The Pod URL parameter to the Libpod Container List
    endpoint has been deprecated; the information previously
    gated by the Pod boolean will now be included in the
    response unconditionally.

  - Change hard requires for AppArmor to Recommends. They
    are not needed for runtime or with SELinux but already
    installed if AppArmor is used [jsc#SMO-15]

  - Add BuildRequires for pkg-config(libselinux) to build
    with SELinux support [jsc#SMO-15] 

Update to v2.0.4

  - Fixed a bug where the output of podman image search did
    not populate the Description field as it was mistakenly
    assigned to the ID field.

  - Fixed a bug where podman build - and podman build on an
    HTTP target would fail.

  - Fixed a bug where rootless Podman would improperly chown
    the copied-up contents of anonymous volumes (#7130).

  - Fixed a bug where Podman would sometimes HTML-escape
    special characters in its CLI output.

  - Fixed a bug where the podman start --attach
    --interactive command would print the container ID of
    the container attached to when exiting (#7068).

  - Fixed a bug where podman run --ipc=host --pid=host would
    only set --pid=host and not --ipc=host (#7100).

  - Fixed a bug where the --publish argument to podman run,
    podman create and podman pod create would not allow
    binding the same container port to more than one host
    port (#7062).

  - Fixed a bug where incorrect arguments to podman images
    --format could cause Podman to segfault.

  - Fixed a bug where podman rmi --force on an image ID with
    more than one name and at least one container using the
    image would not completely remove containers using the
    image (#7153).

  - Fixed a bug where memory usage in bytes and memory use
    percentage were swapped in the output of podman stats

    --format=json.

  - Fixed a bug where the libpod and compat events endpoints
    would fail if no filters were specified (#7078).

  - Fixed a bug where the CgroupVersion field in responses
    from the compat Info endpoint was prefixed by 'v'
    (instead of just being '1' or '2', as is documented).

  - Suggest katacontainers instead of recommending it. It's
    not enabled by default, so it's just bloat

Update to v2.0.3

  - Fix handling of entrypoint

  - log API: add context to allow for cancelling

  - fix API: Create container with an invalid configuration

  - Remove all instances of named return 'err' from Libpod

  - Fix: Correct connection counters for hijacked
    connections

  - Fix: Hijacking v2 endpoints to follow rfc 7230 semantics

  - Remove hijacked connections from active connections list

  - version/info: format: allow more json variants

  - Correctly print STDOUT on non-terminal remote exec

  - Fix container and pod create commands for remote create

  - Mask out /sys/dev to prevent information leak from the
    host

  - Ensure sig-proxy default is propagated in start

  - Add SystemdMode to inspect for containers

  - When determining systemd mode, use full command

  - Fix lint

  - Populate remaining unused fields in `pod inspect`

  - Include infra container information in `pod inspect`

  - play-kube: add suport for 'IfNotPresent' pull type

  - docs: user namespace can't be shared in pods

  - Fix 'Error: unrecognized protocol \'TCP\' in port
    mapping'

  - Error on rootless mac and ip addresses

  - Fix & add notes regarding problematic language in
    codebase

  - abi: set default umask and rlimits

  - Used reference package with errors for parsing tag

  - fix: system df error when an image has no name

  - Fix Generate API title/description

  - Add noop function disable-content-trust

  - fix play kube doesn't override dockerfile ENTRYPOINT

  - Support default profile for apparmor

  - Bump github.com/containers/common to v0.14.6

  - events endpoint: backwards compat to old type

  - events endpoint: fix panic and race condition

  - Switch references from libpod.conf to containers.conf

  - podman.service: set type to simple

  - podman.service: set doc to podman-system-service

  - podman.service: use default registries.conf

  - podman.service: use default killmode

  - podman.service: remove stop timeout

  - systemd: symlink user->system

  - vendor golang.org/x/text@v0.3.3

  - Fix a bug where --pids-limit was parsed incorrectly

  - search: allow wildcards

  - [CI:DOCS]Do not copy policy.json into gating image

  - Fix systemd pid 1 test

  - Cirrus: Rotate keys post repo. rename

  - The libpod.conf(5) man page got removed and all
    references are now pointing towards containers.conf(5),
    which will be part of the libcontainers-common package.

Update to podman v2.0.2

  - fix race condition in `libpod.GetEvents(...)`

  - Fix bug where `podman mount` didn't error as rootless

  - remove podman system connection

  - Fix imports to ensure v2 is used with libpod

  - Update release notes for v2.0.2

  - specgen: fix order for setting rlimits

  - Ensure umask is set appropriately for 'system service'

  - generate systemd: improve pod-flags filter

  - Fix a bug with APIv2 compat network remove to log an
    ErrNetworkNotFound instead of nil

  - Fixes --remote flag issues

  - Pids-limit should only be set if the user set it

  - Set console mode for windows

  - Allow empty host port in --publish flag

  - Add a note on the APIs supported by `system service`

  - fix: Don't override entrypoint if it's `nil`

  - Set TMPDIR to /var/tmp by default if not set

  - test: add tests for --user and volumes

  - container: move volume chown after spec generation

  - libpod: volume copyup honors namespace mappings

  - Fix `system service` panic from early hangup in events

  - stop podman service in e2e tests

  - Print errors from individual containers in pods

  - auto-update: clarify systemd-unit requirements

  - podman ps truncate the command

  - move go module to v2

  - Vendor containers/common v0.14.4

  - Bump to imagebuilder v1.1.6 on v2 branch

  - Account for non-default port number in image name

  - Changes since v2.0.1

  - Update release notes with further v2.0.1 changes

  - Fix inspect to display multiple label: changes

  - Set syslog for exit commands on log-level=debug

  - Friendly amendment for pr 6751

  - podman run/create: support all transports

  - systemd generate: allow manual restart of container
    units in pods

  - Revert sending --remote flag to containers

  - Print port mappings in `ps` for ctrs sharing network

  - vendor github.com/containers/common@v0.14.3

  - Update release notes for v2.0.1

  - utils: drop default mapping when running uid!=0

  - Set stop signal to 15 when not explicitly set

  - podman untag: error if tag doesn't exist

  - Reformat inspect network settings

  - APIv2: Return `StatusCreated` from volume creation

  - APIv2:fix: Remove `/json` from compat network EPs

  - Fix ssh-agent support

  - libpod: specify mappings to the storage

  - APIv2:doc: Fix swagger doc to refer to volumes

  - Add podman network to bash command completions

  - Fix typo in manpage for `podman auto update`.

  - Add JSON output field for ps

  - V2 podman system connection

  - image load: no args required

  - Re-add PODMAN_USERNS environment variable

  - Fix conflicts between privileged and other flags

  - Bump required go version to 1.13

  - Add explicit command to alpine container in test case.

  - Use POLL_DURATION for timer

  - Stop following logs using timers

  - 'pod' was being truncated to 'po' in the names of the
    generated systemd unit files.

  - rootless_linux: improve error message

  - Fix podman build handling of --http-proxy flag

  - correct the absolute path of `rm` executable

  - Makefile: allow customizable GO_BUILD

  - Cirrus: Change DEST_BRANCH to v2.0

Update to podman v2.0.0

  - The `podman generate systemd` command now supports the
    `--new` flag when used with pods, allowing portable
    services for pods to be created.

  - The `podman play kube` command now supports running
    Kubernetes Deployment YAML.

  - The `podman exec` command now supports the `--detach`
    flag to run commands in the container in the background.

  - The `-p` flag to `podman run` and `podman create` now
    supports forwarding ports to IPv6 addresses.

  - The `podman run`, `podman create` and `podman pod
    create` command now support a `--replace` flag to remove
    and replace any existing container (or, for `pod
    create`, pod) with the same name

  - The `--restart-policy` flag to `podman run` and `podman
    create` now supports the `unless-stopped` restart
    policy.

  - The `--log-driver` flag to `podman run` and `podman
    create` now supports the `none` driver, which does not
    log the container's output.

  - The `--mount` flag to `podman run` and `podman create`
    now accepts `readonly` option as an alias to `ro`.

  - The `podman generate systemd` command now supports the
    `--container-prefix`, `--pod-prefix`, and `--separator`
    arguments to control the name of generated unit files.

  - The `podman network ls` command now supports the
    `--filter` flag to filter results.

  - The `podman auto-update` command now supports specifying
    an authfile to use when pulling new images on a
    per-container basis using the
    `io.containers.autoupdate.authfile` label.

  - Fixed a bug where the `podman exec` command would log to
    journald when run in containers loggined to journald
    ([#6555](https://github.com/containers/libpod/issues/655
    5)).

  - Fixed a bug where the `podman auto-update` command would
    not preserve the OS and architecture of the original
    image when pulling a replacement
    ([#6613](https://github.com/containers/libpod/issues/661
    3)).

  - Fixed a bug where the `podman cp` command could create
    an extra `merged` directory when copying into an
    existing directory
    ([#6596](https://github.com/containers/libpod/issues/659
    6)).

  - Fixed a bug where the `podman pod stats` command would
    crash on pods run with `--network=host`
    ([#5652](https://github.com/containers/libpod/issues/565
    2)).

  - Fixed a bug where containers logs written to journald
    did not include the name of the container.

  - Fixed a bug where the `podman network inspect` and
    `podman network rm` commands did not properly handle
    non-default CNI configuration paths
    ([#6212](https://github.com/containers/libpod/issues/621
    2)).

  - Fixed a bug where Podman did not properly remove
    containers when using the Kata containers OCI runtime.

  - Fixed a bug where `podman inspect` would sometimes
    incorrectly report the network mode of containers
    started with `--net=none`.

  - Podman is now better able to deal with cases where
    `conmon` is killed before the container it is
    monitoring.

Update to podman v1.9.3 :

  - Fixed a bug where, on FIPS enabled hosts, FIPS mode
    secrets were not properly mounted into containers

  - Fixed a bug where builds run over Varlink would hang

  - Fixed a bug where podman save would fail when the target
    image was specified by digest

  - Fixed a bug where rootless containers with ports
    forwarded to them could panic and dump core due to a
    concurrency issue (#6018)

  - Fixed a bug where rootless Podman could race when
    opening the rootless user namespace, resulting in
    commands failing to run

  - Fixed a bug where HTTP proxy environment variables
    forwarded into the container by the --http-proxy flag
    could not be overridden by --env or --env-file

  - Fixed a bug where rootless Podman was setting resource
    limits on cgroups v2 systems that were not using
    systemd-managed cgroups (and thus did not support
    resource limits), resulting in containers failing to
    start

Update podman to v1.9.1 :

  - Bugfixes

  - Fixed a bug where healthchecks could become
    nonfunctional if container log paths were manually set
    with --log-path and multiple container logs were placed
    in the same directory

  - Fixed a bug where rootless Podman could, when using an
    older libpod.conf, print numerous warning messages about
    an invalid CGroup manager config

  - Fixed a bug where rootless Podman would sometimes fail
    to close the rootless user namespace when joining it

Update podman to v1.9.0 :

  - Features

  - Experimental support has been added for podman run

    --userns=auto, which automatically allocates a unique
    UID and GID range for the new container's user namespace

  - The podman play kube command now has a --network flag to
    place the created pod in one or more CNI networks

  - The podman commit command now supports an --iidfile flag
    to write the ID of the committed image to a file

  - Initial support for the new containers.conf
    configuration file has been added. containers.conf
    allows for much more detailed configuration of some
    Podman functionality

  - Changes

  - There has been a major cleanup of the podman info
    command resulting in breaking changes. Many fields have
    been renamed to better suit usage with APIv2

  - All uses of the --timeout flag have been switched to
    prefer the alternative --time. The --timeout flag will
    continue to work, but man pages and --help will use the
    --time flag instead

  - Bugfixes

  - Fixed a bug where some volume mounts from the host would
    sometimes not properly determine the flags they should
    use when mounting

  - Fixed a bug where Podman was not propagating $PATH to
    Conmon and the OCI runtime, causing issues for some OCI
    runtimes that required it

  - Fixed a bug where rootless Podman would print error
    messages about missing support for systemd cgroups when
    run in a container with no cgroup support

  - Fixed a bug where podman play kube would not properly
    handle container-only port mappings (#5610)

  - Fixed a bug where the podman container prune command was
    not pruning containers in the created and configured
    states

  - Fixed a bug where Podman was not properly removing CNI
    IP address allocations after a reboot (#5433)

  - Fixed a bug where Podman was not properly applying the
    default Seccomp profile when --security-opt was not
    given at the command line

  - HTTP API

  - Many Libpod API endpoints have been added, including
    Changes, Checkpoint, Init, and Restore

  - Resolved issues where the podman system service command
    would time out and exit while there were still active
    connections

  - Stability overall has greatly improved as we prepare the
    API for a beta release soon with Podman 2.0

  - Misc

  - The default infra image for pods has been upgraded to
    k8s.gcr.io/pause:3.2 (from 3.1) to address a bug in the
    architecture metadata for non-AMD64 images

  - The slirp4netns networking utility in rootless Podman
    now uses Seccomp filtering where available for improved
    security

  - Updated Buildah to v1.14.8

  - Updated containers/storage to v1.18.2

  - Updated containers/image to v5.4.3

  - Updated containers/common to v0.8.1

  - Add 'systemd' BUILDFLAGS to build with support for
    journald logging (bsc#1162432)

Update podman to v1.8.2 :

  - Features

  - Initial support for automatically updating containers
    managed via Systemd unit files has been merged. This
    allows containers to automatically upgrade if a newer
    version of their image becomes available

  - Bugfixes

  - Fixed a bug where unit files generated by podman
    generate systemd --new would not force containers to
    detach, causing the unit to time out when trying to
    start

  - Fixed a bug where podman system reset could delete
    important system directories if run as rootless on
    installations created by older Podman (#4831)

  - Fixed a bug where image built by podman build would not
    properly set the OS and Architecture they were built
    with (#5503)

  - Fixed a bug where attached podman run with --sig-proxy
    enabled (the default), when built with Go 1.14, would
    repeatedly send signal 23 to the process in the
    container and could generate errors when the container
    stopped (#5483)

  - Fixed a bug where rootless podman run commands could
    hang when forwarding ports

  - Fixed a bug where rootless Podman would not work when
    /proc was mounted with the hidepid option set

  - Fixed a bug where the podman system service command
    would use large amounts of CPU when --timeout was set to
    0 (#5531)

  - HTTP API

  - Initial support for Libpod endpoints related to creating
    and operating on image manifest lists has been added

  - The Libpod Healthcheck and Events API endpoints are now
    supported

  - The Swagger endpoint can now handle cases where no
    Swagger documentation has been generated

Update podman to v1.8.1 :

  - Features

  - Many networking-related flags have been added to podman
    pod create to enable customization of pod networks,
    including

    --add-host, --dns, --dns-opt, --dns-search, --ip,

    --mac-address, --network, and --no-hosts

  - The podman ps --format=json command now includes the ID
    of the image containers were created with

  - The podman run and podman create commands now feature an

    --rmi flag to remove the image the container was using
    after it exits (if no other containers are using said
    image)
    ([#4628](https://github.com/containers/libpod/issues/462
    8))

  - The podman create and podman run commands now support
    the

    --device-cgroup-rule flag (#4876)

  - While the HTTP API remains in alpha, many fixes and
    additions have landed. These are documented in a
    separate subsection below

  - The podman create and podman run commands now feature a

    --no-healthcheck flag to disable healthchecks for a
    container (#5299)

  - Containers now recognize the io.containers.capabilities
    label, which specifies a list of capabilities required
    by the image to run. These capabilities will be used as
    long as they are more restrictive than the default
    capabilities used

  - YAML produced by the podman generate kube command now
    includes SELinux configuration passed into the container
    via

    --security-opt label=... (#4950)

  - Bugfixes

  - Fixed CVE-2020-1726, a security issue where volumes
    manually populated before first being mounted into a
    container could have those contents overwritten on first
    being mounted into a container

  - Fixed a bug where Podman containers with user namespaces
    in CNI networks with the DNS plugin enabled would not
    have the DNS plugin's nameserver added to their
    resolv.conf
    ([#5256](https://github.com/containers/libpod/issues/525
    6))

  - Fixed a bug where trailing / characters in image volume
    definitions could cause them to not be overridden by a
    user-specified mount at the same location
    ([#5219](https://github.com/containers/libpod/issues/521
    9))

  - Fixed a bug where the label option in libpod.conf, used
    to disable SELinux by default, was not being respected
    (#5087)

  - Fixed a bug where the podman login and podman logout
    commands required the registry to log into be specified
    (#5146)

  - Fixed a bug where detached rootless Podman containers
    could not forward ports (#5167)

  - Fixed a bug where rootless Podman could fail to run if
    the pause process had died

  - Fixed a bug where Podman ignored labels that were
    specified with only a key and no value (#3854)

  - Fixed a bug where Podman would fail to create named
    volumes when the backing filesystem did not support
    SELinux labelling (#5200)

  - Fixed a bug where --detach-keys='' would not disable
    detaching from a container (#5166)

  - Fixed a bug where the podman ps command was too
    aggressive when filtering containers and would force
    --all on in too many situations

  - Fixed a bug where the podman play kube command was
    ignoring image configuration, including volumes, working
    directory, labels, and stop signal (#5174)

  - Fixed a bug where the Created and CreatedTime fields in
    podman images --format=json were misnamed, which also
    broke Go template output for those fields
    ([#5110](https://github.com/containers/libpod/issues/511
    0))

  - Fixed a bug where rootless Podman containers with ports
    forwarded could hang when started (#5182)

  - Fixed a bug where podman pull could fail to parse
    registry names including port numbers

  - Fixed a bug where Podman would incorrectly attempt to
    validate image OS and architecture when starting
    containers

  - Fixed a bug where Bash completion for podman build -f
    would not list available files that could be built
    (#3878)

  - Fixed a bug where podman commit --change would perform
    incorrect validation, resulting in valid changes being
    rejected (#5148)

  - Fixed a bug where podman logs --tail could take large
    amounts of memory when the log file for a container was
    large (#5131)

  - Fixed a bug where Podman would sometimes incorrectly
    generate firewall rules on systems using firewalld

  - Fixed a bug where the podman inspect command would not
    display network information for containers properly if a
    container joined multiple CNI networks
    ([#4907](https://github.com/containers/libpod/issues/490
    7))

  - Fixed a bug where the --uts flag to podman create and
    podman run would only allow specifying containers by
    full ID (#5289)

  - Fixed a bug where rootless Podman could segfault when
    passed a large number of file descriptors

  - Fixed a bug where the podman port command was
    incorrectly interpreting additional arguments as
    container names, instead of port numbers

  - Fixed a bug where units created by podman generate
    systemd did not depend on network targets, and so could
    start before the system network was ready (#4130)

  - Fixed a bug where exec sessions in containers which did
    not specify a user would not inherit supplemental groups
    added to the container via --group-add

  - Fixed a bug where Podman would not respect the $TMPDIR
    environment variable for placing large temporary files
    during some operations (e.g. podman pull)
    ([#5411](https://github.com/containers/libpod/issues/541
    1))

  - HTTP API

  - Initial support for secure connections to servers via
    SSH tunneling has been added

  - Initial support for the libpod create and logs endpoints
    for containers has been added

  - Added a /swagger/ endpoint to serve API documentation

  - The json endpoint for containers has received many fixes

  - Filtering images and containers has been greatly
    improved, with many bugs fixed and documentation
    improved

  - Image creation endpoints (commit, pull, etc) have seen
    many fixes

  - Server timeout has been fixed so that long operations
    will no longer trigger the timeout and shut the server
    down

  - The stats endpoint for containers has seen major fixes
    and now provides accurate output

  - Handling the HTTP 304 status code has been fixed for all
    endpoints

  - Many fixes have been made to API documentation to ensure
    it matches the code

  - Misc

  - The Created field to podman images --format=json has
    been renamed to CreatedSince as part of the fix for
    (#5110). Go templates using the old name shou ld still
    work

  - The CreatedTime field to podman images --format=json has
    been renamed to CreatedAt as part of the fix for
    (#5110). Go templates using the old name should still
    work

  - The before filter to podman images has been renamed to
    since for Docker compatibility. Using before will still
    work, but documentation has been changed to use the new
    since filter

  - Using the --password flag to podman login now warns that
    passwords are being passed in plaintext

  - Some common cases where Podman would deadlock have been
    fixed to warn the user that podman system renumber must
    be run to resolve the deadlock

  - Configure br_netfilter for podman automatically
    (bsc#1165738) The trigger is only excuted when updating
    podman-cni-config while the command was running

conmon was update to v2.0.20 (bsc#1175821)

  - journald: fix logging container name

  - container logging: Implement none driver - 'off', 'null'
    or 'none' all work.

  - ctrl: warn if we fail to unlink

  - Drop fsync calls

  - Reap PIDs before running exit command

  - Fix log path parsing

  - Add --sync option to prevent conmon from double forking

  - Add --no-sync-log option to instruct conmon to not sync
    the logs of the containers upon shutting down. This
    feature fixes a regression where we unconditionally
    dropped the log sync. It is possible the container logs
    could be corrupted on a sudden power-off. If you need
    container logs to remain in consistent state after a
    sudden shutdown, please update from v2.0.19 to v2.0.20

  - Update to v2.0.17 :

  - Add option to delay execution of exit command

  - Update to v2.0.16 :

  - tty: flush pending data when fd is ready

  - Enable support for journald logging (bsc#1162432)

  - Update to v2.0.15 :

  - store status while waiting for pid

  - Update to v2.0.14 :

  - drop usage of splice(2)

  - avoid hanging on stdin

  - stdio: sometimes quit main loop after io is done

  - ignore sigpipe

  - Update to v2.0.12

  - oom: fix potential race between verification steps

  - Update to v2.0.11

  - log: reject --log-tag with k8s-file

  - chmod std files pipes

  - adjust score to -1000 to prevent conmon from ever being
    OOM killed

  - container OOM: verify cgroup hasn't been cleaned up
    before reporting OOM

  - journal logging: write to /dev/null instead of -1

fuse-overlayfs was updated to 1.1.2 (bsc#1175821) :

  - fix memory leak when creating whiteout files.

  - fix lookup for overflow uid when it is different than
    the overflow gid.

  - use openat2(2) when available.

  - accept 'ro' as mount option.

  - fix set mtime for a symlink.

  - fix some issues reported by static analysis.

  - fix potential infinite loop on a short read.

  - fix creating a directory if the destination already
    exists in the upper layer.

  - report correctly the number of links for a directory
    also for subsequent stat calls

  - stop looking up the ino in the lower layers if the file
    could not be opened

  - make sure the destination is deleted before doing a
    rename(2). It prevents a left over directory to cause
    delete to fail with EEXIST.

  - honor --debug.

libcontainers-common was updated to fix :

  - Fixes for %_libexecdir changing to /usr/libexec
    (bsc#1174075)

  - Added containers/common tarball for containers.conf(5)
    man page

  - Install containers.conf default configuration in
    /usr/share/containers

  - libpod repository on github got renamed to podman

  - Update to image 5.5.1

  - Add documentation for credHelpera

  - Add defaults for using the rootless policy path

  - Update libpod/podman to 2.0.3

  - docs: user namespace can't be shared in pods

  - Switch references from libpod.conf to containers.conf

  - Allow empty host port in --publish flag

  - update document login see config.json as valid

  - Update storage to 1.20.2

  - Add back skip_mount_home

  - Remove remaining difference between SLE and openSUSE
    package and ship the some mounts.conf default
    configuration on both platforms. As the sources for the
    mount point do not exist on openSUSE by default this
    config will basically have no effect on openSUSE.
    (jsc#SLE-12122, bsc#1175821) 

  - Update to image 5.4.4

  - Remove registries.conf VERSION 2 references from man
    page

  - Intial authfile man page

  - Add $HOME/.config/containers/certs.d to
    perHostCertDirPath

  - Add $HOME/.config/containers/registries.conf to config
    path

  - registries.conf.d: add stances for the registries.conf

  - update to libpod 1.9.3

  - userns: support --userns=auto

  - Switch to using --time as opposed to --timeout to better
    match Docker

  - Add support for specifying CNI networks in podman play
    kube

  - man pages: fix inconsistencies

  - Update to storage 1.19.1

  - userns: add support for auto

  - store: change the default user to containers

  - config: honor XDG_CONFIG_HOME

  - Remove the /var/lib/ca-certificates/pem/SUSE.pem
    workaround again. It never ended up in SLES and a
    different way to fix the underlying problem is being
    worked on.

  - Add registry.opensuse.org as default registry
    [bsc#1171578] 

  - Add /var/lib/ca-certificates/pem/SUSE.pem to the SLES
    mounts. This for making container-suseconnect working in
    the public cloud on-demand images. It needs that file
    for being able to verify the server certificates of the
    RMT servers hosted in the public cloud.
    (https://github.com/SUSE/container-suseconnect/issues/41
    ) 

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://localhost/v1.40/_ping"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com//issues/7230]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/SUSE/container-suseconnect/issues/41"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/4628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/4907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/5110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/5219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/5256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/5411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/5652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/6212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/6555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/6596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/6613"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected conmon / fuse-overlayfs / libcontainers-common / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:conmon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcontainers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman-cni-config");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"conmon-2.0.20-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"conmon-debuginfo-2.0.20-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fuse-overlayfs-1.1.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fuse-overlayfs-debuginfo-1.1.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fuse-overlayfs-debugsource-1.1.2-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcontainers-common-20200727-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"podman-2.0.6-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"podman-cni-config-2.0.6-lp152.4.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "conmon / conmon-debuginfo / fuse-overlayfs / etc");
}
