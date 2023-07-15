##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5423-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161248);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-20770",
    "CVE-2022-20771",
    "CVE-2022-20785",
    "CVE-2022-20792",
    "CVE-2022-20796"
  );
  script_xref(name:"USN", value:"5423-2");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : ClamAV vulnerabilities (USN-5423-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5423-2 advisory.

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in HTML file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20785)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in CHM file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20770)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in the TIFF file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20771)

  - A vulnerability in the regex module used by the signature database load module of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an authenticated,
    local attacker to crash ClamAV at database load time, and possibly gain code execution. The vulnerability
    is due to improper bounds checking that may result in a multi-byte heap buffer overwflow write. An
    attacker could exploit this vulnerability by placing a crafted CDB ClamAV signature database file in the
    ClamAV database directory. An exploit could allow the attacker to run code as the clamav user.
    (CVE-2022-20792)

  - On May 4, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in Clam AntiVirus (ClamAV) versions 0.103.4,
    0.103.5, 0.104.1, and 0.104.2 could allow an authenticated, local attacker to cause a denial of service
    condition on an affected device. For a description of this vulnerability, see the ClamAV blog.
    (CVE-2022-20796)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5423-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-20792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
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
    {'osver': '16.04', 'pkgname': 'clamav', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.6+dfsg-0ubuntu0.16.04.1+esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav / clamav-base / clamav-daemon / clamav-freshclam / etc');
}
