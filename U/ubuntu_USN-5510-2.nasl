##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5510-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163055);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-2319", "CVE-2022-2320");
  script_xref(name:"USN", value:"5510-2");

  script_name(english:"Ubuntu 16.04 ESM : X.Org X Server vulnerabilities (USN-5510-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5510-2 advisory.

  - A flaw was found in the Xorg-x11-server. The specific flaw exists within the handling of
    ProcXkbSetDeviceInfo requests. The issue results from the lack of proper validation of user-supplied data,
    which can result in a memory access past the end of an allocated buffer. This flaw allows an attacker to
    escalate privileges and execute arbitrary code in the context of root. (CVE-2022-2320)

  - A flaw was found in the Xorg-x11-server. An out-of-bounds access issue can occur in the ProcXkbSetGeometry
    function due to improper validation of the request length. (CVE-2022-2319)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5510-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2320");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland-hwe-16.04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'xdmx', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xmir', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xmir-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm1'},
    {'osver': '16.04', 'pkgname': 'xnest', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xorg-server-source-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm1'},
    {'osver': '16.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xserver-xephyr-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm1'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm1'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-dev-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm1'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-legacy-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm1'},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xvfb', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xwayland', 'pkgver': '2:1.18.4-0ubuntu0.12+esm2'},
    {'osver': '16.04', 'pkgname': 'xwayland-hwe-16.04', 'pkgver': '2:1.19.6-1ubuntu4.1~16.04.6+esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xmir / xmir-hwe-16.04 / xnest / etc');
}
