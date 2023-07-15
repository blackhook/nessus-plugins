#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-398.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135004);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/02");

  script_cve_id("CVE-2019-18466");

  script_name(english:"openSUSE Security Update : cni / cni-plugins / conmon / etc (openSUSE-2020-398)");
  script_summary(english:"Check for the openSUSE-2020-398 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cni, cni-plugins, conmon, fuse-overlayfs, podman fixes
the following issues :

podman was updated to 1.8.0 :

  - CVE-2019-18466: Fixed a bug where podman cp would
    improperly copy files on the host when copying a symlink
    in the container that included a glob operator (#3829
    bsc#1155217)

  - The name of the cni-bridge in the default config changed
    from 'cni0' to 'podman-cni0' with podman-1.6.0. Add a
    %trigger to rename the bridge in the system to the new
    default if it exists. The trigger is only excuted when
    updating podman-cni-config from something older than
    1.6.0. This is mainly needed for SLE where we're
    updating from 1.4.4 to 1.8.0 (bsc#1160460).

Update podman to v1.8.0 (bsc#1160460) :

  - Features

  - The podman system service command has been added,
    providing a preview of Podman's new Docker-compatible
    API. This API is still very new, and not yet ready for
    production use, but is available for early testing

  - Rootless Podman now uses Rootlesskit for port
    forwarding, which should greatly improve performance and
    capabilities

  - The podman untag command has been added to remove tags
    from images without deleting them

  - The podman inspect command on images now displays
    previous names they used

  - The podman generate systemd command now supports a --new
    option to generate service files that create and run new
    containers instead of managing existing containers

  - Support for --log-opt tag= to set logging tags has been
    added to the journald log driver

  - Added support for using Seccomp profiles embedded in
    images for podman run and podman create via the new
    --seccomp-policy CLI flag

  - The podman play kube command now honors pull policy

  - Bugfixes

  - Fixed a bug where the podman cp command would not copy
    the contents of directories when paths ending in /. were
    given

  - Fixed a bug where the podman play kube command did not
    properly locate Seccomp profiles specified relative to
    localhost

  - Fixed a bug where the podman info command for remote
    Podman did not show registry information

  - Fixed a bug where the podman exec command did not
    support having input piped into it

  - Fixed a bug where the podman cp command with rootless
    Podman on CGroups v2 systems did not properly determine
    if the container could be paused while copying

  - Fixed a bug where the podman container prune --force
    command could possible remove running containers if they
    were started while the command was running 

  - Fixed a bug where Podman, when run as root, would not
    properly configure slirp4netns networking when requested

  - Fixed a bug where podman run --userns=keep-id did not
    work when the user had a UID over 65535

  - Fixed a bug where rootless podman run and podman create
    with the --userns=keep-id option could change
    permissions on /run/user/$UID and break KDE

  - Fixed a bug where rootless Podman could not be run in a
    systemd service on systems using CGroups v2

  - Fixed a bug where podman inspect would show CPUShares as
    0, instead of the default (1024), when it was not
    explicitly set

  - Fixed a bug where podman-remote push would segfault

  - Fixed a bug where image healthchecks were not shown in
    the output of podman inspect

  - Fixed a bug where named volumes created with containers
    from pre-1.6.3 releases of Podman would be autoremoved
    with their containers if the --rm flag was given, even
    if they were given names

  - Fixed a bug where podman history was not computing image
    sizes correctly

  - Fixed a bug where Podman would not error on invalid
    values to the --sort flag to podman images

  - Fixed a bug where providing a name for the image made by
    podman commit was mandatory, not optional as it should
    be

  - Fixed a bug where the remote Podman client would append
    an extra ' to %PATH

  - Fixed a bug where the podman build command would
    sometimes ignore the -f option and build the wrong
    Containerfile

  - Fixed a bug where the podman ps --filter command would
    only filter running containers, instead of all
    containers, if

    --all was not passed

  - Fixed a bug where the podman load command on compressed
    images would leave an extra copy on disk

  - Fixed a bug where the podman restart command would not
    properly clean up the network, causing it to function
    differently from podman stop; podman start

  - Fixed a bug where setting the --memory-swap flag to
    podman create and podman run to -1 (to indicate
    unlimited) was not supported

  - Misc

  - Initial work on version 2 of the Podman remote API has
    been merged, but is still in an alpha state and not
    ready for use. Read more here

  - Many formatting corrections have been made to the
    manpages

  - The changes to address (#5009) may cause anonymous
    volumes created by Podman versions 1.6.3 to 1.7.0 to not
    be removed when their container is removed

  - Updated vendored Buildah to v1.13.1

  - Updated vendored containers/storage to v1.15.8

  - Updated vendored containers/image to v5.2.0

  - Add apparmor-abstractions as required runtime dependency
    to have `tunables/global` available.

  - fixed the --force flag for the 'container prune'
    command.
    (https://github.com/containers/libpod/issues/4844)

Update podman to v1.7.0

  - Features

  - Added support for setting a static MAC address for
    containers

  - Added support for creating macvlan networks with podman
    network create, allowing Podman containers to be
    attached directly to networks the host is connected to

  - The podman image prune and podman container prune
    commands now support the --filter flag to filter what
    will be pruned, and now prompts for confirmation when
    run without --force (#4410 and #4411)

  - Podman now creates CGroup namespaces by default on
    systems using CGroups v2 (#4363)

  - Added the podman system reset command to remove all
    Podman files and perform a factory reset of the Podman
    installation

  - Added the --history flag to podman images to display
    previous names used by images (#4566)

  - Added the --ignore flag to podman rm and podman stop to
    not error when requested containers no longer exist

  - Added the --cidfile flag to podman rm and podman stop to
    read the IDs of containers to be removed or stopped from
    a file

  - The podman play kube command now honors Seccomp
    annotations (#3111)

  - The podman play kube command now honors RunAsUser,
    RunAsGroup, and selinuxOptions

  - The output format of the podman version command has been
    changed to better match docker version when using the

    --format flag

  - Rootless Podman will no longer initialize
    containers/storage twice, removing a potential deadlock
    preventing Podman commands from running while an image
    was being pulled (#4591)

  - Added tmpcopyup and notmpcopyup options to the --tmpfs
    and

    --mount type=tmpfs flags to podman create and podman run
    to control whether the content of directories are copied
    into tmpfs filesystems mounted over them

  - Added support for disabling detaching from containers by
    setting empty detach keys via --detach-keys=''

  - The podman build command now supports the --pull and

    --pull-never flags to control when images are pulled
    during a build

  - The podman ps -p command now shows the name of the pod
    as well as its ID (#4703)

  - The podman inspect command on containers will now
    display the command used to create the container

  - The podman info command now displays information on
    registry mirrors (#4553)

  - Bugfixes

  - Fixed a bug where Podman would use an incorrect runtime
    directory as root, causing state to be deleted after
    root logged out and making Podman in systemd services
    not function properly

  - Fixed a bug where the --change flag to podman import and
    podman commit was not being parsed properly in many
    cases

  - Fixed a bug where detach keys specified in libpod.conf
    were not used by the podman attach and podman exec
    commands, which always used the global default
    ctrl-p,ctrl-q key combination (#4556)

  - Fixed a bug where rootless Podman was not able to run
    podman pod stats even on CGroups v2 enabled systems
    (#4634)

  - Fixed a bug where rootless Podman would fail on kernels
    without the renameat2 syscall (#4570)

  - Fixed a bug where containers with chained network
    namespace dependencies (IE, container A using --net
    container=B and container B using --net container=C)
    would not properly mount /etc/hosts and /etc/resolv.conf
    into the container (#4626)

  - Fixed a bug where podman run with the --rm flag and
    without

    -d could, when run in the background, throw a 'container
    does not exist' error when attempting to remove the
    container after it exited

  - Fixed a bug where named volume locks were not properly
    reacquired after a reboot, potentially leading to
    deadlocks when trying to start containers using the
    volume (#4605 and #4621)

  - Fixed a bug where Podman could not completely remove
    containers if sent SIGKILL during removal, leaving the
    container name unusable without the podman rm --storage
    command to complete removal (#3906)

  - Fixed a bug where checkpointing containers started with
    --rm was allowed when --export was not specified (the
    container, and checkpoint, would be removed after
    checkpointing was complete by --rm) (#3774)

  - Fixed a bug where the podman pod prune command would
    fail if containers were present in the pods and the
    --force flag was not passed (#4346)

  - Fixed a bug where containers could not set a static IP
    or static MAC address if they joined a non-default CNI
    network (#4500)

  - Fixed a bug where podman system renumber would always
    throw an error if a container was mounted when it was
    run

  - Fixed a bug where podman container restore would fail
    with containers using a user namespace

  - Fixed a bug where rootless Podman would attempt to use
    the journald events backend even on systems without
    systemd installed

  - Fixed a bug where podman history would sometimes not
    properly identify the IDs of layers in an image (#3359)

  - Fixed a bug where containers could not be restarted when
    Conmon v2.0.3 or later was used

  - Fixed a bug where Podman did not check image OS and
    Architecture against the host when starting a container

  - Fixed a bug where containers in pods did not function
    properly with the Kata OCI runtime (#4353)

  - Fixed a bug where `podman info --format '(( json . ))'
    would not produce JSON output (#4391)

  - Fixed a bug where Podman would not verify if files
    passed to

    --authfile existed (#4328)

  - Fixed a bug where podman images --digest would not
    always print digests when they were available

  - Fixed a bug where rootless podman run could hang due to
    a race with reading and writing events

  - Fixed a bug where rootless Podman would print
    warning-level logs despite not be instructed to do so
    (#4456)

  - Fixed a bug where podman pull would attempt to fetch
    from remote registries when pulling an unqualified image
    using the docker-daemon transport (#4434)

  - Fixed a bug where podman cp would not work if STDIN was
    a pipe

  - Fixed a bug where podman exec could stop accepting input
    if anything was typed between the command being run and
    the exec session starting (#4397)

  - Fixed a bug where podman logs --tail 0 would print all
    lines of a container's logs, instead of no lines (#4396)

  - Fixed a bug where the timeout for slirp4netns was
    incorrectly set, resulting in an extremely long timeout
    (#4344)

  - Fixed a bug where the podman stats command would print
    CPU utilizations figures incorrectly (#4409)

  - Fixed a bug where the podman inspect --size command
    would not print the size of the container's read/write
    layer if the size was 0 (#4744)

  - Fixed a bug where the podman kill command was not
    properly validating signals before use (#4746)

  - Fixed a bug where the --quiet and --format flags to
    podman ps could not be used at the same time

  - Fixed a bug where the podman stop command was not
    stopping exec sessions when a container was created
    without a PID namespace (--pid=host)

  - Fixed a bug where the podman pod rm --force command was
    not removing anonymous volumes for containers that were
    removed

  - Fixed a bug where the podman checkpoint command would
    not export all changes to the root filesystem of the
    container if performed more than once on the same
    container (#4606)

  - Fixed a bug where containers started with --rm would not
    be automatically removed on being stopped if an exec
    session was running inside the container (#4666)

  - Misc

  - The fixes to runtime directory path as root can cause
    strange behavior if an upgrade is performed while
    containers are running

  - Updated vendored Buildah to v1.12.0

  - Updated vendored containers/storage library to v1.15.4

  - Updated vendored containers/image library to v5.1.0

  - Kata Containers runtimes (kata-runtime, kata-qemu, and
    kata-fc) are now present in the default libpod.conf, but
    will not be available unless Kata containers is
    installed on the system

  - Podman previously did not allow the creation of
    containers with a memory limit lower than 4MB. This
    restriction has been removed, as the crun runtime can
    create containers with significantly less memory

Update podman to v1.6.4

  - Remove winsz FIFO on container restart to allow use with
    Conmon 2.03 and higher

  - Ensure volumes reacquire locks on system restart,
    preventing deadlocks when starting containers

  - Suppress spurious log messages when running rootless
    Podman

  - Update vendored containers/storage to v1.13.6

  - Fix a deadlock related to writing events

  - Do not use the journald event logger when it is not
    available

Update podman to v1.6.2

  - Features

  - Added a --runtime flag to podman system migrate to allow
    the OCI runtime for all containers to be reset, to ease
    transition to the crun runtime on CGroups V2 systems
    until runc gains full support

  - The podman rm command can now remove containers in
    broken states which previously could not be removed

  - The podman info command, when run without root, now
    shows information on UID and GID mappings in the
    rootless user namespace

  - Added podman build --squash-all flag, which squashes all
    layers (including those of the base image) into one
    layer

  - The --systemd flag to podman run and podman create now
    accepts a string argument and allows a new value,
    always, which forces systemd support without checking if
    the the container entrypoint is systemd

  - Bugfixes

  - Fixed a bug where the podman top command did not work on
    systems using CGroups V2 (#4192)

  - Fixed a bug where rootless Podman could double-close a
    file, leading to a panic

  - Fixed a bug where rootless Podman could fail to retrieve
    some containers while refreshing the state

  - Fixed a bug where podman start --attach
    --sig-proxy=false would still proxy signals into the
    container

  - Fixed a bug where Podman would unconditionally use a
    non-default path for authentication credentials
    (auth.json), breaking podman login integration with
    skopeo and other tools using the containers/image
    library

  - Fixed a bug where podman ps --format=json and podman
    images

    --format=json would display null when no results were
    returned, instead of valid JSON

  - Fixed a bug where podman build --squash was incorrectly
    squashing all layers into one, instead of only new
    layers

  - Fixed a bug where rootless Podman would allow volumes
    with options to be mounted (mounting volumes requires
    root), creating an inconsistent state where volumes
    reported as mounted but were not (#4248)

  - Fixed a bug where volumes which failed to unmount could
    not be removed (#4247)

  - Fixed a bug where Podman incorrectly handled some errors
    relating to unmounted or missing containers in
    containers/storage

  - Fixed a bug where podman stats was broken on systems
    running CGroups V2 when run rootless (#4268)

  - Fixed a bug where the podman start command would print
    the short container ID, instead of the full ID

  - Fixed a bug where containers created with an OCI runtime
    that is no longer available (uninstalled or removed from
    the config file) would not appear in podman ps and could
    not be removed via podman rm

  - Fixed a bug where containers restored via podman
    container restore --import would retain the CGroup path
    of the original container, even if their container ID
    changed; thus, multiple containers created from the same
    checkpoint would all share the same CGroup

  - Misc

  - The default PID limit for containers is now set to 4096.
    It can be adjusted back to the old default (unlimited)
    by passing

    --pids-limit 0 to podman create and podman run

  - The podman start --attach command now automatically
    attaches STDIN if the container was created with -i

  - The podman network create command now validates network
    names using the same regular expression as container and
    pod names

  - The --systemd flag to podman run and podman create will
    now only enable systemd mode when the binary being run
    inside the container is /sbin/init, /usr/sbin/init, or
    ends in systemd (previously detected any path ending in
    init or systemd)

  - Updated vendored Buildah to 1.11.3

  - Updated vendored containers/storage to 1.13.5

  - Updated vendored containers/image to 4.0.1

Update podman to v1.6.1

  - Features

  - The podman network create, podman network rm, podman
    network inspect, and podman network ls commands have
    been added to manage CNI networks used by Podman

  - The podman volume create command can now create and
    mount volumes with options, allowing volumes backed by
    NFS, tmpfs, and many other filesystems

  - Podman can now run containers without CGroups for better
    integration with systemd by using the --cgroups=disabled
    flag with podman create and podman run. This is
    presently only supported with the crun OCI runtime

  - The podman volume rm and podman volume inspect commands
    can now refer to volumes by an unambiguous partial name,
    in addition to full name (e.g. podman volume rm myvol to
    remove a volume named myvolume) (#3891)

  - The podman run and podman create commands now support
    the

    --pull flag to allow forced re-pulling of images (#3734)

  - Mounting volumes into a container using --volume,
    --mount, and

    --tmpfs now allows the suid, dev, and exec mount options
    (the inverse of nosuid, nodev, noexec) (#3819)

  - Mounting volumes into a container using --mount now
    allows the relabel=Z and relabel=z options to relabel
    mounts.

  - The podman push command now supports the --digestfile
    option to save a file containing the pushed digest

  - Pods can now have their hostname set via podman pod
    create

    --hostname or providing Pod YAML with a hostname set to
    podman play kube (#3732)

  - The podman image sign command now supports the
    --cert-dir flag

  - The podman run and podman create commands now support
    the

    --security-opt label=filetype:$LABEL flag to set the
    SELinux label for container files

  - The remote Podman client now supports healthchecks

  - Bugfixes

  - Fixed a bug where remote podman pull would panic if a
    Varlink connection was not available (#4013)

  - Fixed a bug where podman exec would not properly set
    terminal size when creating a new exec session (#3903)

  - Fixed a bug where podman exec would not clean up socket
    symlinks on the host (#3962)

  - Fixed a bug where Podman could not run systemd in
    containers that created a CGroup namespace

  - Fixed a bug where podman prune -a would attempt to prune
    images used by Buildah and CRI-O, causing errors (#3983)

  - Fixed a bug where improper permissions on the ~/.config
    directory could cause rootless Podman to use an
    incorrect directory for storing some files

  - Fixed a bug where the bash completions for podman import
    threw errors

  - Fixed a bug where Podman volumes created with podman
    volume create would not copy the contents of their
    mountpoint the first time they were mounted into a
    container (#3945)

  - Fixed a bug where rootless Podman could not run podman
    exec when the container was not run inside a CGroup
    owned by the user (#3937)

  - Fixed a bug where podman play kube would panic when
    given Pod YAML without a securityContext (#3956)

  - Fixed a bug where Podman would place files incorrectly
    when storage.conf configuration items were set to the
    empty string (#3952)

  - Fixed a bug where podman build did not correctly inherit
    Podman's CGroup configuration, causing crashed on
    CGroups V2 systems (#3938)

  - Fixed a bug where remote podman run --rm would exit
    before the container was completely removed, allowing
    race conditions when removing container resources
    (#3870)

  - Fixed a bug where rootless Podman would not properly
    handle changes to /etc/subuid and /etc/subgid after a
    container was launched

  - Fixed a bug where rootless Podman could not include some
    devices in a container using the --device flag (#3905)

  - Fixed a bug where the commit Varlink API would segfault
    if provided incorrect arguments (#3897)

  - Fixed a bug where temporary files were not properly
    cleaned up after a build using remote Podman (#3869)

  - Fixed a bug where podman remote cp crashed instead of
    reporting it was not yet supported (#3861)

  - Fixed a bug where podman exec would run as the wrong
    user when execing into a container was started from an
    image with Dockerfile USER (or a user specified via
    podman run --user) (#3838)

  - Fixed a bug where images pulled using the oci: transport
    would be improperly named

  - Fixed a bug where podman varlink would hang when managed
    by systemd due to SD_NOTIFY support conflicting with
    Varlink (#3572)

  - Fixed a bug where mounts to the same destination would
    sometimes not trigger a conflict, causing a race as to
    which was actually mounted

  - Fixed a bug where podman exec --preserve-fds caused
    Podman to hang (#4020)

  - Fixed a bug where removing an unmounted container that
    was unmounted might sometimes not properly clean up the
    container (#4033)

  - Fixed a bug where the Varlink server would freeze when
    run in a systemd unit file (#4005)

  - Fixed a bug where Podman would not properly set the
    $HOME environment variable when the OCI runtime did not
    set it

  - Fixed a bug where rootless Podman would incorrectly
    print warning messages when an OCI runtime was not found
    (#4012)

  - Fixed a bug where named volumes would conflict with,
    instead of overriding, tmpfs filesystems added by the
    --read-only-tmpfs flag to podman create and podman run

  - Fixed a bug where podman cp would incorrectly make the
    target directory when copying to a symlink which pointed
    to a nonexistent directory (#3894)

  - Fixed a bug where remote Podman would incorrectly read
    STDIN when the -i flag was not set (#4095)

  - Fixed a bug where podman play kube would create an empty
    pod when given an unsupported YAML type (#4093)

  - Fixed a bug where podman import --change improperly
    parsed CMD (#4000)

  - Fixed a bug where rootless Podman on systems using
    CGroups V2 would not function with the cgroupfs CGroups
    manager

  - Fixed a bug where rootless Podman could not correctly
    identify the DBus session address, causing containers to
    fail to start (#4162)

  - Fixed a bug where rootless Podman with slirp4netns
    networking would fail to start containers due to mount
    leaks

  - Misc

  - Significant changes were made to Podman volumes in this
    release. If you have pre-existing volumes, it is
    strongly recommended to run podman system renumber after
    upgrading.

  - Version 0.8.1 or greater of the CNI Plugins is now
    required for Podman

  - Version 2.0.1 or greater of Conmon is strongly
    recommended

  - Updated vendored Buildah to v1.11.2

  - Updated vendored containers/storage library to v1.13.4

  - Improved error messages when trying to create a pod with
    no name via podman play kube

  - Improved error messages when trying to run podman pause
    or podman stats on a rootless container on a system
    without CGroups V2 enabled

  - TMPDIR has been set to /var/tmp by default to better
    handle large temporary files

  - podman wait has been optimized to detect stopped
    containers more rapidly

  - Podman containers now include a ContainerManager
    annotation indicating they were created by libpod

  - The podman info command now includes information about
    slirp4netns and fuse-overlayfs if they are available

  - Podman no longer sets a default size of 65kb for tmpfs
    filesystems

  - The default Podman CNI network has been renamed in an
    attempt to prevent conflicts with CRI-O when both are
    run on the same system. This should only take effect on
    system restart

  - The output of podman volume inspect has been more
    closely matched to docker volume inspect

  - Add katacontainers as a recommended package, and include
    it as an additional OCI runtime in the configuration.

Update podman to v1.5.1

  - Features

  - The hostname of pods is now set to the pod's name

  - Bugfixes

  - Fixed a bug where podman run and podman create did not
    honor the --authfile option (#3730)

  - Fixed a bug where containers restored with podman
    container restore

    --import would incorrectly duplicate the Conmon PID file
    of the original container

  - Fixed a bug where podman build ignored the default OCI
    runtime configured in libpod.conf

  - Fixed a bug where podman run --rm (or force-removing any
    running container with podman rm --force) were not
    retrieving the correct exit code (#3795)

  - Fixed a bug where Podman would exit with an error if any
    configured hooks directory was not present

  - Fixed a bug where podman inspect and podman commit would
    not use the correct CMD for containers run with podman
    play kube

  - Fixed a bug created pods when using rootless Podman and
    CGroups V2 (#3801)

  - Fixed a bug where the podman events command with the
    --since or --until options could take a very long time
    to complete

  - Misc

  - Rootless Podman will now inherit OCI runtime
    configuration from the root configuration (#3781)

  - Podman now properly sets a user agent while contacting
    registries (#3788)

  - Add zsh completion for podman commands

Update podman to v1.5.0

  - Features

  - Podman containers can now join the user namespaces of
    other containers with --userns=container:$ID, or a user
    namespace at an arbitary path with --userns=ns:$PATH

  - Rootless Podman can experimentally squash all UIDs and
    GIDs in an image to a single UID and GID (which does not
    require use of the newuidmap and newgidmap executables)
    by passing

    --storage-opt ignore_chown_errors

  - The podman generate kube command now produces YAML for
    any bind mounts the container has created (#2303)

  - The podman container restore command now features a new
    flag,

    --ignore-static-ip, that can be used with --import to
    import a single container with a static IP multiple
    times on the same host

  - Added the ability for podman events to output JSON by
    specifying --format=json

  - If the OCI runtime or conmon binary cannot be found at
    the paths specified in libpod.conf, Podman will now also
    search for them in the calling user's path

  - Added the ability to use podman import with URLs (#3609)

  - The podman ps command now supports filtering names using
    regular expressions (#3394)

  - Rootless Podman containers with --privileged set will
    now mount in all host devices that the user can access

  - The podman create and podman run commands now support
    the

    --env-host flag to forward all environment variables
    from the host into the container

  - Rootless Podman now supports healthchecks (#3523)

  - The format of the HostConfig portion of the output of
    podman inspect on containers has been improved and
    synced with Docker

  - Podman containers now support CGroup namespaces, and can
    create them by passing --cgroupns=private to podman run
    or podman create

  - The podman create and podman run commands now support
    the

    --ulimit=host flag, which uses any ulimits currently set
    on the host for the container

  - The podman rm and podman rmi commands now use different
    exit codes to indicate 'no such container' and
    'container is running' errors

  - Support for CGroups V2 through the crun OCI runtime has
    been greatly improved, allowing resource limits to be
    set for rootless containers when the CGroups V2
    hierarchy is in use

  - Bugfixes

  - Fixed a bug where a race condition could cause podman
    restart to fail to start containers with ports

  - Fixed a bug where containers restored from a checkpoint
    would not properly report the time they were started at

  - Fixed a bug where podman search would return at most 25
    results, even when the maximum number of results was set
    higher

  - Fixed a bug where podman play kube would not honor
    capabilities set in imported YAML (#3689)

  - Fixed a bug where podman run --env, when passed a single
    key (to use the value from the host), would set the
    environment variable in the container even if it was not
    set on the host (#3648)

  - Fixed a bug where podman commit --changes would not
    properly set environment variables

  - Fixed a bug where Podman could segfault while working
    with images with no history

  - Fixed a bug where podman volume rm could remove
    arbitrary volumes if given an ambiguous name (#3635)

  - Fixed a bug where podman exec invocations leaked memory
    by not cleaning up files in tmpfs

  - Fixed a bug where the --dns and --net=container flags to
    podman run and podman create were not mutually exclusive
    (#3553)

  - Fixed a bug where rootless Podman would be unable to run
    containers when less than 5 UIDs were available

  - Fixed a bug where containers in pods could not be
    removed without removing the entire pod (#3556)

  - Fixed a bug where Podman would not properly clean up all
    CGroup controllers for created cgroups when using the
    cgroupfs CGroup driver

  - Fixed a bug where Podman containers did not properly
    clean up files in tmpfs, resulting in a memory leak as
    containers stopped

  - Fixed a bug where healthchecks from images would not use
    default settings for interval, retries, timeout, and
    start period when they were not provided by the image
    (#3525)

  - Fixed a bug where healthchecks using the HEALTHCHECK CMD
    format where not properly supported (#3507)

  - Fixed a bug where volume mounts using relative source
    paths would not be properly resolved (#3504)

  - Fixed a bug where podman run did not use authorization
    credentials when a custom path was specified (#3524)

  - Fixed a bug where containers checkpointed with podman
    container checkpoint did not properly set their finished
    time

  - Fixed a bug where running podman inspect on any
    container not created with podman run or podman create
    (for example, pod infra containers) would result in a
    segfault (#3500)

  - Fixed a bug where healthcheck flags for podman create
    and podman run were incorrectly named (#3455)

  - Fixed a bug where Podman commands would fail to find
    targets if a partial ID was specified that was ambiguous
    between a container and pod (#3487)

  - Fixed a bug where restored containers would not have the
    correct SELinux label

  - Fixed a bug where Varlink endpoints were not working
    properly if more was not correctly specified

  - Fixed a bug where the Varlink PullImage endpoint would
    crash if an error occurred (#3715)

  - Fixed a bug where the --mount flag to podman create and
    podman run did not allow boolean arguments for its ro
    and rw options (#2980)

  - Fixed a bug where pods did not properly share the UTS
    namespace, resulting in incorrect behavior from some
    utilities which rely on hostname (#3547)

  - Fixed a bug where Podman would unconditionally append
    ENTRYPOINT to CMD during podman commit (and when
    reporting CMD in podman inspect) (#3708)

  - Fixed a bug where podman events with the journald events
    backend would incorrectly print 6 previous events when
    only new events were requested (#3616)

  - Fixed a bug where podman port would exit prematurely
    when a port number was specified (#3747)

  - Fixed a bug where passing . as an argument to the
    --dns-search flag to podman create and podman run was
    not properly clearing DNS search domains in the
    container

  - Misc

  - Updated vendored Buildah to v1.10.1

  - Updated vendored containers/image to v3.0.2

  - Updated vendored containers/storage to v1.13.1

  - Podman now requires conmon v2.0.0 or higher

  - The podman info command now displays the events logger
    being in use

  - The podman inspect command on containers now includes
    the ID of the pod a container has joined and the PID of
    the container's conmon process

  - The -v short flag for podman --version has been re-added

  - Error messages from podman pull should be significantly
    clearer

  - The podman exec command is now available in the remote
    client

  - The podman-v1.5.0.tar.gz file attached is podman
    packaged for MacOS. It can be installed using Homebrew.

  - Update libpod.conf to support latest path discovery
    feature for `runc` and `conmon` binaries.

conmon was included in version 2.0.10. (bsc#1160460, bsc#1164390,
jsc#ECO-1048, jsc#SLE-11485, jsc#SLE-11331) :

fuse-overlayfs was updated to v0.7.6 (bsc#1160460)

  - do not look in lower layers for the ino if there is no
    origin xattr set

  - attempt to use the file path if the operation on the fd
    fails with ENXIO

  - do not expose internal xattrs through listxattr and
    getxattr

  - fix fallocate for deleted files.

  - ignore O_DIRECT. It causes issues with libfuse not using
    an aligned buffer, causing write(2) to fail with EINVAL.

  - on copyup, do not copy the opaque xattr.

  - fix a wrong lookup for whiteout files, that could happen
    on a double unlink.

  - fix possible segmentation fault in direct_fsync()

  - use the data store to create missing whiteouts

  - after a rename, force a directory reload

  - introduce inodes cache

  - correctly read inode for unix sockets

  - avoid hash map lookup when possible

  - use st_dev for the ino key

  - check whether writeback is supported

  - set_attrs: don't require write to S_IFREG

  - ioctl: do not reuse fi->fh for directories

  - fix skip whiteout deletion optimization

  - store the new mode after chmod

  - support fuse writeback cache and enable it by default

  - add option to disable fsync

  - add option to disable xattrs

  - add option to skip ino number check in lower layers

  - fix fd validity check

  - fix memory leak

  - fix read after free

  - fix type for flistxattr return

  - fix warnings reported by lgtm.com

  - enable parallel dirops

cni was updated to 0.7.1 :

  - Set correct CNI version for 99-loopback.conf

Update to version 0.7.1 (bsc#1160460) :

  - Library changes :

  + invoke : ensure custom envs of CNIArgs are prepended to
    process envs

  + add GetNetworkListCachedResult to CNI interface

  + delegate : allow delegation funcs override CNI_COMMAND
    env automatically in heritance

  - Documentation & Convention changes :

  + Update cnitool documentation for spec v0.4.0

  + Add cni-route-override to CNI plugin list

Update to version 0.7.0 :

  - Spec changes :

  + Use more RFC2119 style language in specification (must,
    should...)

  + add notes about ADD/DEL ordering

  + Make the container ID required and unique.

  + remove the version parameter from ADD and DEL commands.

  + Network interface name matters

  + be explicit about optional and required structure
    members

  + add CHECK method

  + Add a well-known error for 'try again'

  + SPEC.md: clarify meaning of 'routes'

  - Library changes :

  + pkg/types: Makes IPAM concrete type

  + libcni: return error if Type is empty

  + skel: VERSION shouldn't block on stdin

  + non-pointer instances of types.Route now correctly
    marshal to JSON

  + libcni: add ValidateNetwork and ValidateNetworkList
    functions

  + pkg/skel: return error if JSON config has no network
    name

  + skel: add support for plugin version string

  + libcni: make exec handling an interface for better
    downstream testing

  + libcni: api now takes a Context to allow operations to
    be timed out or cancelled

  + types/version: add helper to parse PrevResult

  + skel: only print about message, not errors

  + skel,invoke,libcni: implementation of CHECK method

  + cnitool: Honor interface name supplied via CNI_IFNAME
    environment variable.

  + cnitool: validate correct number of args

  + Don't copy gw from IP4.Gateway to Route.GW When
    converting from 0.2.0

  + add PrintTo method to Result interface

  + Return a better error when the plugin returns none

  - Install sleep binary into CNI plugin directory

cni-plugins was updated to 0.8.4 :

Update to version 0.8.4 (bsc#1160460) :

  - add support for mips64le

  - Add missing cniVersion in README example

  - bump go-iptables module to v0.4.5

  - iptables: add idempotent functions

  - portmap doesn't fail if chain doesn't exist

  - fix portmap port forward flakiness

  - Add Bruce Ma and Piotr Skarmuk as owners

Update to version 0.8.3 :

  - Enhancements :

  - static: prioritize the input sources for IPs (#400).

  - tuning: send gratuitous ARP in case of MAC address
    update (#403).

  - bandwidth: use uint64 for Bandwidth value (#389).

  - ptp: only override DNS conf if DNS settings provided
    (#388).

  - loopback: When prevResults are not supplied to loopback
    plugin, create results to return (#383).

  - loopback support CNI CHECK and result cache (#374).

  - Better input validation :

  - vlan: add MTU validation to loadNetConf (#405).

  - macvlan: add MTU validation to loadNetConf (#404).

  - bridge: check vlan id when loading net conf (#394).

  - Bugfixes :

  - bugfix: defer after err check, or it may panic (#391).

  - portmap: Fix dual-stack support (#379).

  - firewall: don't return error in DEL if prevResult is not
    found (#390).

  - bump up libcni back to v0.7.1 (#377).

  - Docs :

  - contributing doc: revise test script name to run (#396).

  - contributing doc: describe cnitool installation (#397).

Update plugins to v0.8.2

  + New features :

  - Support 'args' in static and tuning

  - Add Loopback DSR support, allow l2tunnel networks to be
    used with the l2bridge plugin

  - host-local: return error if same ADD request is seen
    twice

  - bandwidth: fix collisions

  - Support ips capability in static and mac capability in
    tuning

  - pkg/veth: Make host-side veth name configurable

  + Bug fixes :

  - Fix: failed to set bridge addr: could not add IP address
    to 'cni0': file exists

  - host-device: revert name setting to make retries
    idempotent (#357).

  - Vendor update go-iptables. Vendor update go-iptables to
    obtain commit f1d0510cabcb710d5c5dd284096f81444b9d8d10

  - Update go.mod & go.sub

  - Remove link Down/Up in MAC address change to prevent
    route flush (#364).

  - pkg/ip unit test: be agnostic of Linux version, on Linux
    4.4 the syscall error message is 'invalid argument' not
    'file exists'

  - bump containernetworking/cni to v0.7.1

Updated plugins to v0.8.1 :

  + Bugs :

  - bridge: fix ipMasq setup to use correct source address

  - fix compilation error on 386

  - bandwidth: get bandwidth interface in host ns through
    container interface

  + Improvements :

  - host-device: add pciBusID property

Updated plugins to v0.8.0 :

  + New plugins :

  - bandwidth - limit incoming and outgoing bandwidth

  - firewall - add containers to firewall rules

  - sbr - convert container routes to source-based routes

  - static - assign a fixed IP address

  - win-bridge, win-overlay: Windows plugins

  + Plugin features / changelog :

  - CHECK Support

  - macvlan :

  - Allow to configure empty ipam for macvlan

  - Make master config optional

  - bridge :

  - Add vlan tag to the bridge cni plugin

  - Allow the user to assign VLAN tag

  - L2 bridge Implementation.

  - dhcp :

  - Include Subnet Mask option parameter in DHCPREQUEST

  - Add systemd unit file to activate socket with systemd

  - Add container ifName to the dhcp clientID, making the
    clientID value

  - flannel :

  - Pass through runtimeConfig to delegate

  - host-local :

  - host-local: add ifname to file tracking IP address used

  - host-device :

  - Support the IPAM in the host-device

  - Handle empty netns in DEL for loopback and host-device

  - tuning :

  - adds 'ip link' command related feature into tuning

  + Bug fixes & minor changes

  - Correctly DEL on ipam failure for all plugins

  - Fix bug on ip revert if cmdAdd fails on macvlan and
    host-device

  - host-device: Ensure device is down before rename

  - Fix -hostprefix option

  - some DHCP servers expect to request for explicit router
    options

  - bridge: release IP in case of error

  - change source of ipmasq rule from ipn to ip

from version v0.7.5 :

  + This release takes a minor change to the portmap 
plugin :

  - Portmap: append, rather than prepend, entry rules

  + This fixes a potential issue where firewall rules may be
    bypassed by port mapping

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/containers/libpod/issues/4844"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cni / cni-plugins / conmon / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cni-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:conmon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:podman-cni-config");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"cni-0.7.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cni-plugins-0.8.4-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"conmon-2.0.10-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"conmon-debuginfo-2.0.10-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fuse-overlayfs-0.7.6-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fuse-overlayfs-debuginfo-0.7.6-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"fuse-overlayfs-debugsource-0.7.6-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"podman-1.8.0-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"podman-cni-config-1.8.0-lp151.3.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cni-plugins / cni / conmon / conmon-debuginfo / fuse-overlayfs / etc");
}
