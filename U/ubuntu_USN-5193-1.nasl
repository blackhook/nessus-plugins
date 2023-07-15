#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5193-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156076);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-4008",
    "CVE-2021-4009",
    "CVE-2021-4010",
    "CVE-2021-4011"
  );
  script_xref(name:"USN", value:"5193-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : X.Org X Server vulnerabilities (USN-5193-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5193-1 advisory.

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SwapCreateRegister function. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2021-4011)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcRenderCompositeGlyphs function. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-4008)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcXFixesCreatePointerBarrier function. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-4009)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcScreenSaverSuspend function. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2021-4010)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5193-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland-hwe-18.04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'xdmx', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xmir', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xnest', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xorg-server-source-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.6'},
    {'osver': '18.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xserver-xephyr-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.6'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-core-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.6'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-dev-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.6'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-legacy-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.6'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xvfb', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xwayland', 'pkgver': '2:1.19.6-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'xwayland-hwe-18.04', 'pkgver': '2:1.20.8-2ubuntu2.2~18.04.6'},
    {'osver': '20.04', 'pkgname': 'xdmx', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xnest', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xvfb', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '20.04', 'pkgname': 'xwayland', 'pkgver': '2:1.20.13-1ubuntu1~20.04.2'},
    {'osver': '21.04', 'pkgname': 'xdmx', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xnest', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xvfb', 'pkgver': '2:1.20.11-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'xwayland', 'pkgver': '2:21.1.1-0ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xdmx', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xnest', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xserver-common', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xvfb', 'pkgver': '2:1.20.13-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'xwayland', 'pkgver': '2:21.1.2-0ubuntu1.1'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xmir / xnest / xorg-server-source / etc');
}
