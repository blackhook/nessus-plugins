##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5091-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(154162);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");
  script_xref(name:"USN", value:"5091-3");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel (Azure) regression (USN-5091-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-5091-3 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5091-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-cloud-tools-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-headers-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-tools-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1061-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-20.04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-cloud-tools-5.4.0-1061', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-headers-5.4.0-1061', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-tools-5.4.0-1061', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.4.0.1061.41'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.4.0.1061.41'},
    {'osver': '20.04', 'pkgname': 'linux-azure-cloud-tools-5.4.0-1061', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-azure-headers-5.4.0-1061', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-azure-lts-20.04', 'pkgver': '5.4.0.1061.59'},
    {'osver': '20.04', 'pkgname': 'linux-azure-tools-5.4.0-1061', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-lts-20.04', 'pkgver': '5.4.0.1061.59'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-lts-20.04', 'pkgver': '5.4.0.1061.59'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-lts-20.04', 'pkgver': '5.4.0.1061.59'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-lts-20.04', 'pkgver': '5.4.0.1061.59'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1061-azure', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-lts-20.04', 'pkgver': '5.4.0.1061.59'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-azure / linux-azure-5.4-cloud-tools-5.4.0-1061 / etc');
}
