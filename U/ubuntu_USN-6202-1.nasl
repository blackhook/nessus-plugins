#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6202-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178000);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/05");

  script_cve_id("CVE-2023-25153", "CVE-2023-25173");
  script_xref(name:"USN", value:"6202-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 : containerd vulnerabilities (USN-6202-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-6202-1 advisory.

  - containerd is an open source container runtime. Before versions 1.6.18 and 1.5.18, when importing an OCI
    image, there was no limit on the number of bytes read for certain files. A maliciously crafted image with
    a large file where a limit was not applied could cause a denial of service. This bug has been fixed in
    containerd 1.6.18 and 1.5.18. Users should update to these versions to resolve the issue. As a workaround,
    ensure that only trusted images are used and that only trusted users have permissions to import images.
    (CVE-2023-25153)

  - containerd is an open source container runtime. A bug was found in containerd prior to versions 1.6.18 and
    1.5.18 where supplementary groups are not set up properly inside a container. If an attacker has direct
    access to a container and manipulates their supplementary group access, they may be able to use
    supplementary group access to bypass primary group restrictions in some cases, potentially gaining access
    to sensitive information or gaining the ability to execute code in that container. Downstream applications
    that use the containerd client library may be affected as well. This bug has been fixed in containerd
    v1.6.18 and v.1.5.18. Users should update to these versions and recreate containers to resolve this issue.
    Users who rely on a downstream application that uses containerd's client library should check that
    application for a separate advisory and instructions. As a workaround, ensure that the `USER $USERNAME`
    Dockerfile instruction is not used. Instead, set the container entrypoint to a value similar to
    `ENTRYPOINT [su, -, user]` to allow `su` to properly set up supplementary groups. (CVE-2023-25173)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6202-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected containerd and / or golang-github-containerd-containerd-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25173");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-github-containerd-containerd-dev");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'containerd', 'pkgver': '1.2.6-0ubuntu1~16.04.6+esm4'},
    {'osver': '18.04', 'pkgname': 'containerd', 'pkgver': '1.6.12-0ubuntu1~18.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.6.12-0ubuntu1~18.04.1+esm1'},
    {'osver': '20.04', 'pkgname': 'containerd', 'pkgver': '1.6.12-0ubuntu1~20.04.3'},
    {'osver': '20.04', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.6.12-0ubuntu1~20.04.3'},
    {'osver': '22.04', 'pkgname': 'containerd', 'pkgver': '1.6.12-0ubuntu1~22.04.3'},
    {'osver': '22.04', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.6.12-0ubuntu1~22.04.3'},
    {'osver': '22.10', 'pkgname': 'containerd', 'pkgver': '1.6.12-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.6.12-0ubuntu1~22.10.2'},
    {'osver': '23.04', 'pkgname': 'containerd', 'pkgver': '1.6.12-0ubuntu3.1'},
    {'osver': '23.04', 'pkgname': 'golang-github-containerd-containerd-dev', 'pkgver': '1.6.12-0ubuntu3.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd / golang-github-containerd-containerd-dev');
}
