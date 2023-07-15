#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4969-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150324);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");
  script_xref(name:"USN", value:"4969-3");

  script_name(english:"Ubuntu 21.04 : DHCP regression (USN-4969-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 21.04 host has packages installed that are affected by a vulnerability as referenced in the USN-4969-3
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4969-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-client-ddns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-server-ldap");
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
if (! preg(pattern:"^(21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '21.04', 'pkgname': 'isc-dhcp-client', 'pkgver': '4.4.1-2.2ubuntu6.2'},
    {'osver': '21.04', 'pkgname': 'isc-dhcp-client-ddns', 'pkgver': '4.4.1-2.2ubuntu6.2'},
    {'osver': '21.04', 'pkgname': 'isc-dhcp-common', 'pkgver': '4.4.1-2.2ubuntu6.2'},
    {'osver': '21.04', 'pkgname': 'isc-dhcp-dev', 'pkgver': '4.4.1-2.2ubuntu6.2'},
    {'osver': '21.04', 'pkgname': 'isc-dhcp-relay', 'pkgver': '4.4.1-2.2ubuntu6.2'},
    {'osver': '21.04', 'pkgname': 'isc-dhcp-server', 'pkgver': '4.4.1-2.2ubuntu6.2'},
    {'osver': '21.04', 'pkgname': 'isc-dhcp-server-ldap', 'pkgver': '4.4.1-2.2ubuntu6.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'isc-dhcp-client / isc-dhcp-client-ddns / isc-dhcp-common / etc');
}
