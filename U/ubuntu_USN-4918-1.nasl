##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4918-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148819);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-1252", "CVE-2021-1404", "CVE-2021-1405");
  script_xref(name:"USN", value:"4918-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : ClamAV vulnerabilities (USN-4918-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4918-1 advisory.

  - A vulnerability in the Excel XLM macro parsing module in Clam AntiVirus (ClamAV) Software versions 0.103.0
    and 0.103.1 could allow an unauthenticated, remote attacker to cause a denial of service condition on an
    affected device. The vulnerability is due to improper error handling that may result in an infinite loop.
    An attacker could exploit this vulnerability by sending a crafted Excel file to an affected device. An
    exploit could allow the attacker to cause the ClamAV scanning process hang, resulting in a denial of
    service condition. (CVE-2021-1252)

  - A vulnerability in the PDF parsing module in Clam AntiVirus (ClamAV) Software versions 0.103.0 and 0.103.1
    could allow an unauthenticated, remote attacker to cause a denial of service condition on an affected
    device. The vulnerability is due to improper buffer size tracking that may result in a heap buffer over-
    read. An attacker could exploit this vulnerability by sending a crafted PDF file to an affected device. An
    exploit could allow the attacker to cause the ClamAV scanning process to crash, resulting in a denial of
    service condition. (CVE-2021-1404)

  - A vulnerability in the email parsing module in Clam AntiVirus (ClamAV) Software version 0.103.1 and all
    prior versions could allow an unauthenticated, remote attacker to cause a denial of service condition on
    an affected device. The vulnerability is due to improper variable initialization that may result in an
    NULL pointer read. An attacker could exploit this vulnerability by sending a crafted email to an affected
    device. An exploit could allow the attacker to cause the ClamAV scanning process crash, resulting in a
    denial of service condition. (CVE-2021-1405)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4918-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav9");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'clamav', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.2+dfsg-0ubuntu0.16.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.2+dfsg-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.10', 'pkgname': 'clamav', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'clamav-base', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'clamav-milter', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'clamdscan', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libclamav9', 'pkgver': '0.103.2+dfsg-0ubuntu0.20.10.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav / clamav-base / clamav-daemon / clamav-freshclam / etc');
}