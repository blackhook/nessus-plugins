#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3378-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143753);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2020-14370");

  script_name(english:"SUSE SLES15 Security Update : podman (SUSE-SU-2020:3378-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for podman fixes the following issues :

Security issue fixed :

This release resolves CVE-2020-14370, in which environment variables
could be leaked between containers created using the Varlink API
(bsc#1176804).

Non-security issues fixed :

add dependency to timezone package or podman fails to build a
container (bsc#1178122)

Install new auto-update system units

Update to v2.1.1 (bsc#1178392) :

  - Changes

  - The `podman info` command now includes the cgroup
    manager Podman is using.

  - API

  - The REST API now includes a Server header in all
    responses.

  - Fixed a bug where the Libpod and Compat Attach endpoints
    could terminate early, before sending all output from
    the container.

  - Fixed a bug where the Compat Create endpoint for
    containers did not properly handle the Interactive
    parameter.

  - Fixed a bug where the Compat Kill endpoint for
    containers could continue to run after a fatal error.

  - Fixed a bug where the Limit parameter of the Compat List
    endpoint for Containers did not properly handle a limit
    of 0 (returning nothing, instead of all containers)
    [#7722].

  - The Libpod Stats endpoint for containers is being
    deprecated and will be replaced by a similar endpoint
    with additional features in a future release.

Changes in v2.1.0

  - Features

  - A new command, `podman image mount`, has been added.
    This allows for an image to be mounted, read-only, to
    inspect its contents without creating a container from
    it [#1433].

  - The `podman save` and `podman load` commands can now
    create and load archives containing multiple images
    [#2669].

  - Rootless Podman now supports all `podman network`
    commands, and rootless containers can now be joined to
    networks.

  - The performance of `podman build` on `ADD` and `COPY`
    instructions has been greatly improved, especially when
    a `.dockerignore` is present.

  - The `podman run` and `podman create` commands now
    support a new mode for the `--cgroups` option,
    `--cgroups=split`. Podman will create two cgroups under
    the cgroup it was launched in, one for the container and
    one for Conmon. This mode is useful for running Podman
    in a systemd unit, as it ensures that all processes are
    retained in systemd's cgroup hierarchy [#6400].

  - The `podman run` and `podman create` commands can now
    specify options to slirp4netns by using the `--network`
    option as follows :

`--net slirp4netns:opt1,opt2`. This allows for, among other things,

switching the port forwarder used by slirp4netns away from
rootlessport.

  - The `podman ps` command now features a new option,
    `--storage`, to show containers from Buildah, CRI-O and
    other applications.

  - The `podman run` and `podman create` commands now
    feature a `--sdnotify` option to control the behavior of
    systemd's sdnotify with containers, enabling improved
    support for Podman in `Type=notify` units.

  - The `podman run` command now features a `--preserve-fds`
    opton to pass file descriptors from the host into the
    container

[#6458].

  - The `podman run` and `podman create` commands can now
    create overlay volume mounts, by adding the `:O` option
    to a bind mount

(e.g. `-v /test:/test:O`). Overlay volume mounts will mount a
directory

into a container from the host and allow changes to it, but not write

those changes back to the directory on the host.

  - The `podman play kube` command now supports the Socket
    HostPath type [#7112].

  - The `podman play kube` command now supports read-only
    mounts.

  - The `podman play kube` command now supports setting
    labels on pods from Kubernetes metadata labels.

  - The `podman play kube` command now supports setting
    container restart policy [#7656].

  - The `podman play kube` command now properly handles
    `HostAlias` entries.

  - The `podman generate kube` command now adds entries to
    `/etc/hosts` from `--host-add` generated YAML as
    `HostAlias` entries.

  - The `podman play kube` and `podman generate kube`
    commands now properly support `shareProcessNamespace` to
    share the PID namespace in pods.

  - The `podman volume ls` command now supports the
    `dangling` filter to identify volumes that are dangling
    (not attached to any container).

  - The `podman run` and `podman create` commands now
    feature a `--umask` option to set the umask of the
    created container.

  - The `podman create` and `podman run` commands now
    feature a `--tz` option to set the timezone within the
    container [#5128].

  - Environment variables for Podman can now be added in the
    `containers.conf` configuration file.

  - The `--mount` option of `podman run` and `podman create`
    now supports a new mount type, `type=devpts`, to add a
    `devpts` mount to the container. This is useful for
    containers that want to mount `/dev/` from the host into
    the container, but still create a terminal.

  - The `--security-opt` flag to `podman run` and `podman
    create` now supports a new option, `proc-opts`, to
    specify options for the container's `/proc` filesystem.

  - Podman with the `crun` OCI runtime now supports a new
    option to `podman run` and `podman create`,
    `--cgroup-conf`, which allows for advanced configuration
    of cgroups on cgroups v2 systems.

  - The `podman create` and `podman run` commands now
    support a `--override-variant` option, to override the
    architecture variant of the image that will be pulled
    and ran.

  - A new global option has been added to Podman,
    `--runtime-flags`, which allows for setting flags to use
    when the OCI runtime is called.

  - The `podman manifest add` command now supports the
    `--cert-dir`, `--auth-file`, `--creds`, and
    `--tls-verify` options.

  - Security

  - This release resolves CVE-2020-14370, in which
    environment variables could be leaked between containers
    created using the Varlink API.

  - Changes

  - Podman will now retry pulling an image 3 times if a pull
    fails due to network errors.

  - The `podman exec` command would previously print error
    messages (e.g. `exec session exited with non-zero exit
    code

    -1`) when the command run exited with a non-0 exit code.
    It no

longer does this. The `podman exec` command will still exit with the
same

exit code as the command run in the container did.

  - Error messages when creating a container or pod with a
    name that is already in use have been improved.

  - For read-only containers running systemd init, Podman
    creates a tmpfs filesystem at `/run`. This was
    previously limited to 65k in size and mounted `noexec`,
    but is now unlimited size and mounted `exec`.

  - The `podman system reset` command no longer removes
    configuration files for rootless Podman.

  - API

  - The Libpod API version has been bumped to v2.0.0 due to
    a breaking change in the Image List API.

  - Docker-compatible Volume Endpoints (Create, Inspect,
    List, Remove, Prune) are now available!

  - Added an endpoint for generating systemd unit files for
    containers.

  - The `last` parameter to the Libpod container list
    endpoint now has an alias, `limit` [#6413].

  - The Libpod image list API new returns timestamps in Unix
    format, as integer, as opposed to as strings

  - The Compat Inspect endpoint for containers now includes
    port information in NetworkSettings.

  - The Compat List endpoint for images now features limited
    support for the (deprecated) `filter` query parameter
    [#6797].

  - Fixed a bug where the Compat Create endpoint for
    containers was not correctly handling bind mounts.

  - Fixed a bug where the Compat Create endpoint for
    containers would not return a 404 when the requested
    image was not present.

  - Fixed a bug where the Compat Create endpoint for
    containers did not properly handle Entrypoint and
    Command from images.

  - Fixed a bug where name history information was not
    properly added in the Libpod Image List endpoint.

  - Fixed a bug where the Libpod image search endpoint
    improperly populated the Description field of responses.

  - Added a `noTrunc` option to the Libpod image search
    endpoint.

  - Fixed a bug where the Pod List API would return null,
    instead of an empty array, when no pods were present
    [#7392].

  - Fixed a bug where endpoints that hijacked would do
    perform the hijack too early, before being ready to send
    and receive data [#7195].

  - Fixed a bug where Pod endpoints that can operate on
    multiple containers at once (e.g. Kill, Pause, Unpause,
    Stop) would not forward errors from individual
    containers that failed.

  - The Compat List endpoint for networks now supports
    filtering results [#7462].

  - Fixed a bug where the Top endpoint for pods would return
    both a 500 and 404 when run on a non-existent pod.

  - Fixed a bug where Pull endpoints did not stream progress
    back to the client.

  - The Version endpoints (Libpod and Compat) now provide
    version in a format compatible with Docker.

  - All non-hijacking responses to API requests should not
    include headers with the version of the server.

  - Fixed a bug where Libpod and Compat Events endpoints did
    not send response headers until the first event occurred
    [#7263].

  - Fixed a bug where the Build endpoints (Compat and
    Libpod) did not stream progress to the client.

  - Fixed a bug where the Stats endpoints (Compat and
    Libpod) did not properly handle clients disconnecting.

  - Fixed a bug where the Ignore parameter to the Libpod
    Stop endpoint was not performing properly.

  - Fixed a bug where the Compat Logs endpoint for
    containers did not stream its output in the correct
    format [#7196].

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178392");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14370/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203378-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86678f58");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Containers 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP2-2020-3378=1

SUSE Linux Enterprise Module for Containers 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP1-2020-3378=1

SUSE Enterprise Storage 7 :

zypper in -t patch SUSE-Storage-7-2020-3378=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14370");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:podman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES15", sp:"1", reference:"podman-2.1.1-4.28.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"podman-2.1.1-4.28.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "podman");
}
