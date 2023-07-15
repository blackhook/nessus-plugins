#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5891-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171942);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2023-23914", "CVE-2023-23915", "CVE-2023-23916");
  script_xref(name:"USN", value:"5891-1");
  script_xref(name:"IAVA", value:"2023-A-0008-S");
  script_xref(name:"IAVA", value:"2023-A-0108-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : curl vulnerabilities (USN-5891-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5891-1 advisory.

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality fail when multiple URLs are requested serially. Using its HSTS support, curl can be
    instructed to use HTTPS instead of usingan insecure clear-text HTTP step even when HTTP is provided in the
    URL. ThisHSTS mechanism would however surprisingly be ignored by subsequent transferswhen done on the same
    command line because the state would not be properlycarried on. (CVE-2023-23914)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality to behave incorrectly when multiple URLs are requested in parallel. Using its HSTS
    support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP step even when
    HTTP is provided in the URL. This HSTS mechanism would however surprisingly fail when multiple transfers
    are done in parallel as the HSTS cache file gets overwritten by the most recentlycompleted transfer. A
    later HTTP-only transfer to the earlier host name would then *not* get upgraded properly to HSTS.
    (CVE-2023-23915)

  - An allocation of resources without limits or throttling vulnerability exists in curl <v7.88.0 based on the
    chained HTTP compression algorithms, meaning that a server response can be compressed multiple times and
    potentially with differentalgorithms. The number of acceptable links in this decompression chain
    wascapped, but the cap was implemented on a per-header basis allowing a maliciousserver to insert a
    virtually unlimited number of compression steps simply byusing many headers. The use of such a
    decompression chain could result in a malloc bomb, making curl end up spending enormous amounts of
    allocated heap memory, or trying to and returning out of memory errors. (CVE-2023-23916)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5891-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23914");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'curl', 'pkgver': '7.58.0-2ubuntu3.23'},
    {'osver': '18.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.58.0-2ubuntu3.23'},
    {'osver': '18.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.58.0-2ubuntu3.23'},
    {'osver': '18.04', 'pkgname': 'libcurl4', 'pkgver': '7.58.0-2ubuntu3.23'},
    {'osver': '18.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.58.0-2ubuntu3.23'},
    {'osver': '18.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.58.0-2ubuntu3.23'},
    {'osver': '18.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.58.0-2ubuntu3.23'},
    {'osver': '20.04', 'pkgname': 'curl', 'pkgver': '7.68.0-1ubuntu2.16'},
    {'osver': '20.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.68.0-1ubuntu2.16'},
    {'osver': '20.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.68.0-1ubuntu2.16'},
    {'osver': '20.04', 'pkgname': 'libcurl4', 'pkgver': '7.68.0-1ubuntu2.16'},
    {'osver': '20.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.68.0-1ubuntu2.16'},
    {'osver': '20.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.68.0-1ubuntu2.16'},
    {'osver': '20.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.68.0-1ubuntu2.16'},
    {'osver': '22.04', 'pkgname': 'curl', 'pkgver': '7.81.0-1ubuntu1.8'},
    {'osver': '22.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.81.0-1ubuntu1.8'},
    {'osver': '22.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.81.0-1ubuntu1.8'},
    {'osver': '22.04', 'pkgname': 'libcurl4', 'pkgver': '7.81.0-1ubuntu1.8'},
    {'osver': '22.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.81.0-1ubuntu1.8'},
    {'osver': '22.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.81.0-1ubuntu1.8'},
    {'osver': '22.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.81.0-1ubuntu1.8'},
    {'osver': '22.10', 'pkgname': 'curl', 'pkgver': '7.85.0-1ubuntu0.3'},
    {'osver': '22.10', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.85.0-1ubuntu0.3'},
    {'osver': '22.10', 'pkgname': 'libcurl3-nss', 'pkgver': '7.85.0-1ubuntu0.3'},
    {'osver': '22.10', 'pkgname': 'libcurl4', 'pkgver': '7.85.0-1ubuntu0.3'},
    {'osver': '22.10', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.85.0-1ubuntu0.3'},
    {'osver': '22.10', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.85.0-1ubuntu0.3'},
    {'osver': '22.10', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.85.0-1ubuntu0.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / libcurl4-gnutls-dev / etc');
}
