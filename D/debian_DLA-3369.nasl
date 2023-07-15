#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3369. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(173457);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2019-16884",
    "CVE-2019-19921",
    "CVE-2021-30465",
    "CVE-2022-29162",
    "CVE-2023-27561"
  );

  script_name(english:"Debian DLA-3369-1 : runc - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3369 advisory.

  - runc through 1.0.0-rc8, as used in Docker through 19.03.2-ce and other products, allows AppArmor
    restriction bypass because libcontainer/rootfs_linux.go incorrectly checks mount targets, and thus a
    malicious Docker image can mount over a /proc directory. (CVE-2019-16884)

  - runc through 1.0.0-rc9 has Incorrect Access Control leading to Escalation of Privileges, related to
    libcontainer/rootfs_linux.go. To exploit this, an attacker must be able to spawn two containers with
    custom volume-mount configurations, and be able to run custom images. (This vulnerability does not affect
    Docker due to an implementation detail that happens to block the attack.) (CVE-2019-19921)

  - runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the
    vulnerability, an attacker must be able to create multiple containers with a fairly specific mount
    configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.
    (CVE-2021-30465)

  - runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. A bug
    was found in runc prior to version 1.1.2 where `runc exec --cap` created processes with non-empty
    inheritable Linux process capabilities, creating an atypical Linux environment and enabling programs with
    inheritable file capabilities to elevate those capabilities to the permitted set during execve(2). This
    bug did not affect the container security sandbox as the inheritable set never contained more capabilities
    than were included in the container's bounding set. This bug has been fixed in runc 1.1.2. This fix
    changes `runc exec --cap` behavior such that the additional capabilities granted to the process being
    executed (as specified via `--cap` arguments) do not include inheritable capabilities. In addition, `runc
    spec` is changed to not set any inheritable capabilities in the created example OCI spec (`config.json`)
    file. (CVE-2022-29162)

  - runc through 1.1.4 has Incorrect Access Control leading to Escalation of Privileges, related to
    libcontainer/rootfs_linux.go. To exploit this, an attacker must be able to spawn two containers with
    custom volume-mount configurations, and be able to run custom images. NOTE: this issue exists because of a
    CVE-2019-19921 regression. (CVE-2023-27561)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=942026");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/runc");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3369");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30465");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29162");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27561");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/runc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the runc packages.

For Debian 10 buster, this problem has been fixed in version 1.0.0~rc6+dfsg1-3+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-github-opencontainers-runc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:runc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'golang-github-opencontainers-runc-dev', 'reference': '1.0.0~rc6+dfsg1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'runc', 'reference': '1.0.0~rc6+dfsg1-3+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-opencontainers-runc-dev / runc');
}
