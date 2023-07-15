#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6028-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174458);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id("CVE-2023-28484", "CVE-2023-29469");
  script_xref(name:"USN", value:"6028-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : libxml2 vulnerabilities (USN-6028-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6028-1 advisory.

  - The libxml2 project reports: Hashing of empty dict strings isn't deterministic Fix null deref in
    xmlSchemaFixupComplexType (CVE-2023-28484, CVE-2023-29469)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6028-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libxml2");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libxml2', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm5'},
    {'osver': '16.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm5'},
    {'osver': '16.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm5'},
    {'osver': '16.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm5'},
    {'osver': '18.04', 'pkgname': 'libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.6'},
    {'osver': '22.04', 'pkgname': 'libxml2', 'pkgver': '2.9.13+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.13+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.13+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.13+dfsg-1ubuntu0.3'},
    {'osver': '22.10', 'pkgname': 'libxml2', 'pkgver': '2.9.14+dfsg-1ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.14+dfsg-1ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.14+dfsg-1ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.14+dfsg-1ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2 / libxml2-dev / libxml2-utils / python-libxml2 / etc');
}
