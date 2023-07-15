#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2223-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(128302);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2018-15664", "CVE-2019-6778", "CVE-2019-10152");

  script_name(english:"SUSE SLES15 Security Update : podman, slirp4netns / libcontainers-common (SUSE-SU-2019:2223-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This is a version update for podman to version 1.4.4 (bsc#1143386).

Additional changes by SUSE on top :

Remove fuse-overlayfs because it's (currently) an unsatisfied
dependency on SLE (bsc#1143386)

Update libpod.conf to use correct infra_command

Update libpod.conf to use better versioned pause container

Update libpod.conf to use official kubic pause container

Update libpod.conf to match latest features set: detach_keys,
lock_type, runtime_supports_json

Add podman-remote varlink client

Version update podman to v1.4.4: Features

  - Podman now has greatly improved support for containers
    using multiple OCI runtimes. Containers now remember if
    they were created with a different runtime using
    --runtime and will always use that runtime

  - The cached and delegated options for volume mounts are
    now allowed for Docker compatability (#3340)

  - The podman diff command now supports the --latest flag
    Bugfixes

  - Fixed a bug where rootless Podman would attempt to use
    the entire root configuration if no rootless
    configuration was present for the user, breaking
    rootless Podman for new installations

  - Fixed a bug where rootless Podman's pause process would
    block SIGTERM, preventing graceful system shutdown and
    hanging until the system's init send SIGKILL

  - Fixed a bug where running Podman as root with sudo -E
    would not work after running rootless Podman at least
    once

  - Fixed a bug where options for tmpfs volumes added with
    the --tmpfs flag were being ignored

  - Fixed a bug where images with no layers could not
    properly be displayed and removed by Podman

  - Fixed a bug where locks were not properly freed on
    failure to create a container or pod

  - Fixed a bug where podman cp on a single file would
    create a directory at the target and place the file in
    it (#3384)

  - Fixed a bug where podman inspect --format '{{.Mounts}}'
    would print a hexadecimal address instead of a
    container's mounts

  - Fixed a bug where rootless Podman would not add an entry
    to container's /etc/hosts files for their own hostname
    (#3405)

  - Fixed a bug where podman ps --sync would segfault
    (#3411)

  - Fixed a bug where podman generate kube would produce an
    invalid ports configuration (#3408) Misc

  - Updated containers/storage to v1.12.13

  - Podman now performs much better on systems with heavy
    I/O load

  - The --cgroup-manager flag to podman now shows the
    correct default setting in help if the default was
    overridden by libpod.conf

  - For backwards compatability, setting
    --log-driver=json-file in podman run is now supported as
    an alias for --log-driver=k8s-file. This is considered
    deprecated, and json-file will be moved to a new
    implementation in the future
    ([#3363](https://github.com/containers/libpo\
    d/issues/3363))

  - Podman's default libpod.conf file now allows the crun
    OCI runtime to be used if it is installed

Update podman to v1.4.2: Fixed a bug where Podman could not run
containers using an older version of Systemd as init

Updated vendored Buildah to v1.9.0 to resolve a critical bug with
Dockerfile RUN instructions

The error message for running podman kill on containers that are not
running has been improved

Podman remote client can now log to a file if syslog is not available

The podman exec command now sets its error code differently based on
whether the container does not exist, and the command in the container
does not exist

The podman inspect command on containers now outputs Mounts JSON that
matches that of docker inspect, only including user-specified volumes
and differentiating bind mounts and named volumes

The podman inspect command now reports the path to a container's OCI
spec with the OCIConfigPath key (only included when the container is
initialized or running)

The podman run --mount command now supports the bind-nonrecursive
option for bind mounts

Fixed a bug where podman play kube would fail to create containers due
to an unspecified log driver

Fixed a bug where Podman would fail to build with musl libc

Fixed a bug where rootless Podman using slirp4netns networking in an
environment with no nameservers on the host other than localhost would
result in nonfunctional networking

Fixed a bug where podman import would not properly set environment
variables, discarding their values and retaining only keys

Fixed a bug where Podman would fail to run when built with Apparmor
support but run on systems without the Apparmor kernel module loaded

Remote Podman will now default the username it uses to log in to
remote systems to the username of the current user

Podman now uses JSON logging with OCI runtimes that support it,
allowing for better error reporting

Updated vendored containers/image to v2.0

Update conmon to v0.3.0

Support OOM Monitor under cgroup V2

Add config binary and make target for configuring conmon with a go
library for importing values

Updated podman to version 1.4.0 (bsc#1137860) and (bsc#1135460) Podman
checkpoint and podman restore commands can now be used to migrate
containers between Podman installations on different systems.

The podman cp now supports pause flag.

The remote client now supports a configuration file for
pre-configuring connections to remote Podman installations

CVE-2019-10152: Fixed an iproper dereference of symlinks of the the
podman cp command which introduced in version 1.1.0 (bsc#1136974).

Fixed a bug where podman commit could improperly set environment
variables that contained = characters

Fixed a bug where rootless podman would sometimes fail to start
containers with forwarded ports

Fixed a bug where podman version on the remote client could segfault

Fixed a bug where podman container runlabel would use /proc/self/exe
instead of the path of the Podman command when printing the command
being executed

Fixed a bug where filtering images by label did not work

Fixed a bug where specifying a bing mount or tmpfs mount over an image
volume would cause a container to be unable to start

Fixed a bug where podman generate kube did not work with containers
with named volumes

Fixed a bug where rootless podman would receive permission denied
errors accessing conmon.pid

Fixed a bug where podman cp with a folder specified as target would
replace the folder, as opposed to copying into it

Fixed a bug where rootless Podman commands could double-unlock a lock,
causing a crash

Fixed a bug where podman incorrectly set tmpcopyup on /dev/ mounts,
causing errors when using the Kata containers runtime

Fixed a bug where podman exec would fail on older kernels

Podman commit command is now usable with the Podman remote client

Signature-policy flag has been deprecated

Updated vendored containers/storage and containers/image libraries
with numerous bugfixes

Updated vendored Buildah to v1.8.3

Podman now requires Conmon v0.2.0

The podman cp command is now aliased as podman container cp

Rootless podman will now default init_path using root Podman's
configuration files (/etc/containers/libpod.conf and
/usr/share/containers/libpod.conf) if not overridden in the rootless
configuration

Added fuse-overlayfs dependency to support overlay based rootless
image manipulations

The podman cp command can now read input redirected to STDIN, and
output to STDOUT instead of a file, using - instead of an argument.

The podman remote client now displays version information from both
the client and server in podman version

The podman unshare command has been added, allowing easy entry into
the user namespace set up by rootless Podman (allowing the removal of
files created by rootless podman, among other things)

Fixed a bug where Podman containers with the --rm flag were removing
created volumes when they were automatically removed

Fixed a bug where container and pod locks were incorrectly marked as
released after a system reboot, causing errors on container and pod
removal

Fixed a bug where Podman pods could not be removed if any container in
the pod encountered an error during removal

Fixed a bug where Podman pods run with the cgroupfs CGroup driver
would encounter a race condition during removal, potentially failing
to remove the pod CGroup

Fixed a bug where the podman container checkpoint and podman container
restore commands were not visible in the remote client

Fixed a bug where podman remote ps --ns would not print the
container's namespaces

Fixed a bug where removing stopped containers with healthchecks could
cause an error

Fixed a bug where the default libpod.conf file was causing parsing
errors

Fixed a bug where pod locks were not being freed when pods were
removed, potentially leading to lock exhaustion

Fixed a bug where 'podman run' with SD_NOTIFY set could, on
short-running containers, create an inconsistent state rendering the
container unusable

The remote Podman client now uses the Varlink bridge to establish
remote connections by default

Fixed an issue with apparmor_parser (bsc#1123387)

Update to libpod v1.4.0 (bsc#1137860) :

The podman checkpoint and podman restore commands can now be used to
migrate containers between Podman installations on different systems

The podman cp command now supports a pause flag to pause containers
while copying into them

The remote client now supports a configuration file for
pre-configuring connections to remote Podman installations

Fixed CVE-2019-10152 - The podman cp command improperly dereferenced
symlinks in host context

Fixed a bug where podman commit could improperly set environment
variables that contained = characters

Fixed a bug where rootless Podman would sometimes fail to start
containers with forwarded ports

Fixed a bug where podman version on the remote client could segfault

Fixed a bug where podman container runlabel would use /proc/self/exe
instead of the path of the Podman command when printing the command
being executed

Fixed a bug where filtering images by label did not work

Fixed a bug where specifying a bing mount or tmpfs mount over an image
volume would cause a container to be unable to start

Fixed a bug where podman generate kube did not work with containers
with named volumes

Fixed a bug where rootless Podman would receive permission denied
errors accessing conmon.pid

Fixed a bug where podman cp with a folder specified as target would
replace the folder, as opposed to copying into it

Fixed a bug where rootless Podman commands could double-unlock a lock,
causing a crash

Fixed a bug where Podman incorrectly set tmpcopyup on /dev/ mounts,
causing errors when using the Kata containers runtime

Fixed a bug where podman exec would fail on older kernels

The podman commit command is now usable with the Podman remote client

The --signature-policy flag (used with several image-related commands)
has been deprecated

The podman unshare command now defines two environment variables in
the spawned shell: CONTAINERS_RUNROOT and CONTAINERS_GRAPHROOT,
pointing to temporary and permanent storage for rootless containers

Updated vendored containers/storage and containers/image libraries
with numerous bugfixes

Updated vendored Buildah to v1.8.3

Podman now requires Conmon v0.2.0

The podman cp command is now aliased as podman container cp

Rootless Podman will now default init_path using root Podman's
configuration files (/etc/containers/libpod.conf and
/usr/share/containers/libpod.conf) if not overridden in the rootless
configuration

Update to image v1.5.1

Vendor in latest containers/storage

docker/docker_client: Drop redundant Domain(ref.ref) call

pkg/blobinfocache: Split implementations into subpackages

copy: progress bar: show messages on completion

docs: rename manpages to *.5.command

add container-certs.d.md manpage

pkg/docker/config: Bring auth tests from docker/docker_client_test

Don't allocate a sync.Mutex separately

Update to storage v1.12.10: Add function to parse out mount options
from graphdriver

Merge the disparate parts of all of the Unix-like lockfiles

Fix unix-but-not-Linux compilation

Return XDG_RUNTIME_DIR as RootlessRuntimeDir if set

Cherry-pick moby/moby #39292 for CVE-2018-15664 fixes

lockfile: add RecursiveLock() API

Update generated files

Fix crash on tesing of aufs code

Let consumers know when Layers and Images came from read-only stores

chown: do not change owner for the mountpoint

locks: correctly mark updates to the layers list

CreateContainer: don't worry about mapping layers unless necessary

docs: fix manpage for containers-storage.conf

docs: sort configuration options alphabetically

docs: document OSTree file deduplication

Add missing options to man page for containers-storage

overlay: use the layer idmapping if present

vfs: prefer layer custom idmappings

layers: propagate down the idmapping settings

Recreate symlink when not found

docs: fix manpage for configuration file

docs: add special handling for manpages in sect 5

overlay: fix single-lower test

Recreate symlink when not found

overlay: propagate errors from mountProgram

utils: root in a userns uses global conf file

Fix handling of additional stores

Correctly check permissions on rootless directory

Fix possible integer overflow on 32bit builds

Evaluate device path for lvm

lockfile test: make concurrent RW test determinisitc

lockfile test: make concurrent read tests deterministic

drivers.DirCopy: fix filemode detection

storage: move the logic to detect rootless into utils.go

Don't set (struct flock).l_pid

Improve documentation of getLockfile

Rename getLockFile to createLockerForPath, and document it

Add FILES section to containers-storage.5 man page

add digest locks

drivers/copy: add a non-cgo fallback

slirp4netns was updated to 0.3.0: CVE-2019-6778: Fixed a heap buffer
overflow in tcp_emu() (bsc#1123156)

This update also includes: fuse3 and fuse-overlayfs to support
rootless containers.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1123156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1123387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1135460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1136974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1137860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1143386");
  script_set_attribute(attribute:"see_also", value:"https://github.com/containers/libpo\");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-15664/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10152/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-6778/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192223-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3f6900a");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Containers 15-SP1:zypper in -t patch
SUSE-SLE-Module-Containers-15-SP1-2019-2223=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2223=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15664");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fuse3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fuse3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fuse3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfuse3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfuse3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"fuse-overlayfs-0.4.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"fuse-overlayfs-debuginfo-0.4.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"fuse-overlayfs-debugsource-0.4.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"fuse3-3.6.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"fuse3-debuginfo-3.6.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"fuse3-debugsource-3.6.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libfuse3-3-3.6.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libfuse3-3-debuginfo-3.6.1-3.3.8")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"podman-1.4.4-4.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slirp4netns-0.3.0-3.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slirp4netns-debuginfo-0.3.0-3.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slirp4netns-debugsource-0.3.0-3.3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "podman / slirp4netns / libcontainers-common");
}
