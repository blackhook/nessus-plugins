#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6088-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176064);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2023-25809", "CVE-2023-27561", "CVE-2023-28642");
  script_xref(name:"USN", value:"6088-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : runC vulnerabilities (USN-6088-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6088-1 advisory.

  - runc is a CLI tool for spawning and running containers according to the OCI specification. In affected
    versions it was found that rootless runc makes `/sys/fs/cgroup` writable in following conditons: 1. when
    runc is executed inside the user namespace, and the `config.json` does not specify the cgroup namespace to
    be unshared (e.g.., `(docker|podman|nerdctl) run --cgroupns=host`, with Rootless Docker/Podman/nerdctl) or
    2. when runc is executed outside the user namespace, and `/sys` is mounted with `rbind, ro` (e.g., `runc
    spec --rootless`; this condition is very rare). A container may gain the write access to user-owned cgroup
    hierarchy `/sys/fs/cgroup/user.slice/...` on the host . Other users's cgroup hierarchies are not affected.
    Users are advised to upgrade to version 1.1.5. Users unable to upgrade may unshare the cgroup namespace
    (`(docker|podman|nerdctl) run --cgroupns=private)`. This is the default behavior of Docker/Podman/nerdctl
    on cgroup v2 hosts. or add `/sys/fs/cgroup` to `maskedPaths`. (CVE-2023-25809)

  - runc through 1.1.4 has Incorrect Access Control leading to Escalation of Privileges, related to
    libcontainer/rootfs_linux.go. To exploit this, an attacker must be able to spawn two containers with
    custom volume-mount configurations, and be able to run custom images. NOTE: this issue exists because of a
    CVE-2019-19921 regression. (CVE-2023-27561)

  - runc is a CLI tool for spawning and running containers according to the OCI specification. It was found
    that AppArmor can be bypassed when `/proc` inside the container is symlinked with a specific mount
    configuration. This issue has been fixed in runc version 1.1.5, by prohibiting symlinked `/proc`. See PR
    #3785 for details. users are advised to upgrade. Users unable to upgrade should avoid using an untrusted
    container image. (CVE-2023-28642)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6088-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-github-opencontainers-runc-dev and / or runc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28642");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-github-opencontainers-runc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:runc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'golang-github-opencontainers-runc-dev', 'pkgver': '1.1.4-0ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'runc', 'pkgver': '1.1.4-0ubuntu1~18.04.2'},
    {'osver': '20.04', 'pkgname': 'golang-github-opencontainers-runc-dev', 'pkgver': '1.1.4-0ubuntu1~20.04.3'},
    {'osver': '20.04', 'pkgname': 'runc', 'pkgver': '1.1.4-0ubuntu1~20.04.3'},
    {'osver': '22.04', 'pkgname': 'golang-github-opencontainers-runc-dev', 'pkgver': '1.1.4-0ubuntu1~22.04.3'},
    {'osver': '22.04', 'pkgname': 'runc', 'pkgver': '1.1.4-0ubuntu1~22.04.3'},
    {'osver': '22.10', 'pkgname': 'golang-github-opencontainers-runc-dev', 'pkgver': '1.1.4-0ubuntu1~22.10.3'},
    {'osver': '22.10', 'pkgname': 'runc', 'pkgver': '1.1.4-0ubuntu1~22.10.3'},
    {'osver': '23.04', 'pkgname': 'golang-github-opencontainers-runc-dev', 'pkgver': '1.1.4-0ubuntu3.1'},
    {'osver': '23.04', 'pkgname': 'runc', 'pkgver': '1.1.4-0ubuntu3.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-opencontainers-runc-dev / runc');
}
