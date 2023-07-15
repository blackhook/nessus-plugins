#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5957-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172590);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2018-19105",
    "CVE-2021-21898",
    "CVE-2021-21899",
    "CVE-2021-21900",
    "CVE-2021-45341",
    "CVE-2021-45342",
    "CVE-2021-45343"
  );
  script_xref(name:"USN", value:"5957-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS : LibreCAD vulnerabilities (USN-5957-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5957-1 advisory.

  - LibreCAD 2.1.3 allows remote attackers to cause a denial of service (0x89C04589 write access violation and
    application crash) or possibly have unspecified other impact via a crafted file. (CVE-2018-19105)

  - A code execution vulnerability exists in the dwgCompressor::decompress18() functionality of LibreCad
    libdxfrw 2.2.0-rc2-19-ge02f3580. A specially-crafted .dwg file can lead to an out-of-bounds write. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-21898)

  - A code execution vulnerability exists in the dwgCompressor::copyCompBytes21 functionality of LibreCad
    libdxfrw 2.2.0-rc2-19-ge02f3580. A specially-crafted .dwg file can lead to a heap buffer overflow. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-21899)

  - A code execution vulnerability exists in the dxfRW::processLType() functionality of LibreCad libdxfrw
    2.2.0-rc2-19-ge02f3580. A specially-crafted .dxf file can lead to a use-after-free vulnerability. An
    attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-21900)

  - A buffer overflow vulnerability in CDataMoji of the jwwlib component of LibreCAD 2.2.0-rc3 and older
    allows an attacker to achieve Remote Code Execution using a crafted JWW document. (CVE-2021-45341)

  - A buffer overflow vulnerability in CDataList of the jwwlib component of LibreCAD 2.2.0-rc3 and older
    allows an attacker to achieve Remote Code Execution using a crafted JWW document. (CVE-2021-45342)

  - In LibreCAD 2.2.0, a NULL pointer dereference in the HATCH handling of libdxfrw allows an attacker to
    crash the application using a crafted DXF document. (CVE-2021-45343)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5957-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected librecad and / or librecad-data packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librecad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librecad-data");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'librecad', 'pkgver': '2.0.9-2ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'librecad-data', 'pkgver': '2.0.9-2ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'librecad', 'pkgver': '2.1.2-1ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'librecad-data', 'pkgver': '2.1.2-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'librecad', 'pkgver': '2.1.3-1.2+deb10u1build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librecad-data', 'pkgver': '2.1.3-1.2+deb10u1build0.20.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'librecad / librecad-data');
}
