#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5996-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173861);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2023-26767", "CVE-2023-26768", "CVE-2023-26769");
  script_xref(name:"USN", value:"5996-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Liblouis vulnerabilities (USN-5996-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5996-1 advisory.

  - Buffer Overflow vulnerability found in Liblouis v.3.24.0 allows a remote attacker to cause a denial of
    service via the lou_logFile function at logginc.c endpoint. (CVE-2023-26767)

  - Buffer Overflow vulnerability found in Liblouis v.3.24.0 allows a remote attacker to cause a denial of
    service via the compileTranslationTable.c and lou_setDataPath functions. (CVE-2023-26768)

  - Buffer Overflow vulnerability found in Liblouis Lou_Trace v.3.24.0 allows a remote attacker to cause a
    denial of service via the resolveSubtable function at compileTranslationTabel.c. (CVE-2023-26769)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5996-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26769");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblouis-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblouis-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblouis-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblouis14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblouis20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblouis9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-louis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-louis");
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
    {'osver': '16.04', 'pkgname': 'liblouis-bin', 'pkgver': '2.6.4-2ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'liblouis-data', 'pkgver': '2.6.4-2ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'liblouis-dev', 'pkgver': '2.6.4-2ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'liblouis9', 'pkgver': '2.6.4-2ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-louis', 'pkgver': '2.6.4-2ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python3-louis', 'pkgver': '2.6.4-2ubuntu0.4+esm1'},
    {'osver': '18.04', 'pkgname': 'liblouis-bin', 'pkgver': '3.5.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'liblouis-data', 'pkgver': '3.5.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'liblouis-dev', 'pkgver': '3.5.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'liblouis14', 'pkgver': '3.5.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python-louis', 'pkgver': '3.5.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python3-louis', 'pkgver': '3.5.0-1ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'liblouis-bin', 'pkgver': '3.12.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'liblouis-data', 'pkgver': '3.12.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'liblouis-dev', 'pkgver': '3.12.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'liblouis20', 'pkgver': '3.12.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'python3-louis', 'pkgver': '3.12.0-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'liblouis-bin', 'pkgver': '3.20.0-2ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'liblouis-data', 'pkgver': '3.20.0-2ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'liblouis-dev', 'pkgver': '3.20.0-2ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'liblouis20', 'pkgver': '3.20.0-2ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'python3-louis', 'pkgver': '3.20.0-2ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'liblouis-bin', 'pkgver': '3.22.0-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'liblouis-data', 'pkgver': '3.22.0-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'liblouis-dev', 'pkgver': '3.22.0-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'liblouis20', 'pkgver': '3.22.0-2ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3-louis', 'pkgver': '3.22.0-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liblouis-bin / liblouis-data / liblouis-dev / liblouis14 / liblouis20 / etc');
}
