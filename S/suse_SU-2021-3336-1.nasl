#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3336-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154100);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-30465",
    "CVE-2021-32760",
    "CVE-2021-41089",
    "CVE-2021-41091",
    "CVE-2021-41092",
    "CVE-2021-41103"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3336-1");

  script_name(english:"SUSE SLES12 Security Update : containerd, docker, runc (SUSE-SU-2021:3336-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3336-1 advisory.

  - runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the
    vulnerability, an attacker must be able to create multiple containers with a fairly specific mount
    configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.
    (CVE-2021-30465)

  - containerd is a container runtime. A bug was found in containerd versions prior to 1.4.8 and 1.5.4 where
    pulling and extracting a specially-crafted container image can result in Unix file permission changes for
    existing files in the hosts filesystem. Changes to file permissions can deny access to the expected owner
    of the file, widen access to others, or set extended bits like setuid, setgid, and sticky. This bug does
    not directly allow files to be read, modified, or executed without an additional cooperating process. This
    bug has been fixed in containerd 1.5.4 and 1.4.8. As a workaround, ensure that users only pull images from
    trusted sources. Linux security modules (LSMs) like SELinux and AppArmor can limit the files potentially
    affected by this bug through policies and profiles that prevent containerd from interacting with specific
    files. (CVE-2021-32760)

  - Moby is an open-source project created by Docker to enable software containerization. A bug was found in
    Moby (Docker Engine) where attempting to copy files using `docker cp` into a specially-crafted container
    can result in Unix file permission changes for existing files in the hosts filesystem, widening access
    to others. This bug does not directly allow files to be read, modified, or executed without an additional
    cooperating process. This bug has been fixed in Moby (Docker Engine) 20.10.9. Users should update to this
    version as soon as possible. Running containers do not need to be restarted. (CVE-2021-41089)

  - Moby is an open-source project created by Docker to enable software containerization. A bug was found in
    Moby (Docker Engine) where the data directory (typically `/var/lib/docker`) contained subdirectories with
    insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory
    contents and execute programs. When containers included executable programs with extended permission bits
    (such as `setuid`), unprivileged Linux users could discover and execute those programs. When the UID of an
    unprivileged Linux user on the host collided with the file owner or group inside a container, the
    unprivileged Linux user on the host could discover, read, and modify those files. This bug has been fixed
    in Moby (Docker Engine) 20.10.9. Users should update to this version as soon as possible. Running
    containers should be stopped and restarted for the permissions to be fixed. For users unable to upgrade
    limit access to the host to trusted users. Limit access to host volumes to trusted containers.
    (CVE-2021-41091)

  - Docker CLI is the command line interface for the docker container runtime. A bug was found in the Docker
    CLI where running `docker login my-private-registry.example.com` with a misconfigured configuration file
    (typically `~/.docker/config.json`) listing a `credsStore` or `credHelpers` that could not be executed
    would result in any provided credentials being sent to `registry-1.docker.io` rather than the intended
    private registry. This bug has been fixed in Docker CLI 20.10.9. Users should update to this version as
    soon as possible. For users unable to update ensure that any configured credsStore or credHelpers entries
    in the configuration file reference an installed credential helper that is executable and on the PATH.
    (CVE-2021-41092)

  - containerd is an open source container runtime with an emphasis on simplicity, robustness and portability.
    A bug was found in containerd where container root directories and some plugins had insufficiently
    restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and
    execute programs. When containers included executable programs with extended permission bits (such as
    setuid), unprivileged Linux users could discover and execute those programs. When the UID of an
    unprivileged Linux user on the host collided with the file owner or group inside a container, the
    unprivileged Linux user on the host could discover, read, and modify those files. This vulnerability has
    been fixed in containerd 1.4.11 and containerd 1.5.7. Users should update to these version when they are
    released and may restart containers or update directory permissions to mitigate the vulnerability. Users
    unable to update should limit access to the host to trusted users. Update directory permission on
    container bundles directories. (CVE-2021-41103)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191434");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-October/009566.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?766b520d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30465");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41092");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41103");
  script_set_attribute(attribute:"solution", value:
"Update the affected containerd, docker and / or runc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41103");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:runc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'containerd-1.4.11-16.45.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'containerd-1.4.11-16.45.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'containerd-1.4.11-16.45.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'containerd-1.4.11-16.45.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'docker-20.10.9_ce-98.72.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'docker-20.10.9_ce-98.72.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'docker-20.10.9_ce-98.72.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'docker-20.10.9_ce-98.72.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'runc-1.0.2-16.14.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'runc-1.0.2-16.14.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'runc-1.0.2-16.14.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'},
    {'reference':'runc-1.0.2-16.14.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-12-0'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd / docker / runc');
}
