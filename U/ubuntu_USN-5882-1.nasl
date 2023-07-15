#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5882-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171810);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2015-8979",
    "CVE-2019-1010228",
    "CVE-2021-41687",
    "CVE-2021-41688",
    "CVE-2021-41689",
    "CVE-2021-41690",
    "CVE-2022-2119",
    "CVE-2022-2120",
    "CVE-2022-2121",
    "CVE-2022-43272"
  );
  script_xref(name:"USN", value:"5882-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM / 22.10 : DCMTK vulnerabilities (USN-5882-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5882-1 advisory.

  - Stack-based buffer overflow in the parsePresentationContext function in storescp in DICOM dcmtk-3.6.0 and
    earlier allows remote attackers to cause a denial of service (segmentation fault) via a long string sent
    to TCP port 4242. (CVE-2015-8979)

  - OFFIS.de DCMTK 3.6.3 and below is affected by: Buffer Overflow. The impact is: Possible code execution and
    confirmed Denial of Service. The component is: DcmRLEDecoder::decompress() (file dcrledec.h, line 122).
    The attack vector is: Many scenarios of DICOM file processing (e.g. DICOM to image conversion). The fixed
    version is: 3.6.4, after commit 40917614e. (CVE-2019-1010228)

  - DCMTK through 3.6.6 does not handle memory free properly. The program malloc a heap memory for parsing
    data, but does not free it when error in parsing. Sending specific requests to the dcmqrdb program incur
    the memory leak. An attacker can use it to launch a DoS attack. (CVE-2021-41687)

  - DCMTK through 3.6.6 does not handle memory free properly. The object in the program is free but its
    address is still used in other locations. Sending specific requests to the dcmqrdb program will incur a
    double free. An attacker can use it to launch a DoS attack. (CVE-2021-41688)

  - DCMTK through 3.6.6 does not handle string copy properly. Sending specific requests to the dcmqrdb
    program, it would query its database and copy the result even if the result is null, which can incur a
    head-based overflow. An attacker can use it to launch a DoS attack. (CVE-2021-41689)

  - DCMTK through 3.6.6 does not handle memory free properly. The malloced memory for storing all file
    information are recorded in a global variable LST and are not freed properly. Sending specific requests to
    the dcmqrdb program can incur a memory leak. An attacker can use it to launch a DoS attack.
    (CVE-2021-41690)

  - OFFIS DCMTK's (All versions prior to 3.6.7) service class provider (SCP) is vulnerable to path traversal,
    allowing an attacker to write DICOM files into arbitrary directories under controlled names. This could
    allow remote code execution. (CVE-2022-2119)

  - OFFIS DCMTK's (All versions prior to 3.6.7) service class user (SCU) is vulnerable to relative path
    traversal, allowing an attacker to write DICOM files into arbitrary directories under controlled names.
    This could allow remote code execution. (CVE-2022-2120)

  - OFFIS DCMTK's (All versions prior to 3.6.7) has a NULL pointer dereference vulnerability while processing
    DICOM files, which may result in a denial-of-service condition. (CVE-2022-2121)

  - DCMTK v3.6.7 was discovered to contain a memory leak via the T_ASC_Association object. (CVE-2022-43272)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5882-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2120");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dcmtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk5");
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
    {'osver': '16.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.1~20150924-5ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.1~20150924-5ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libdcmtk5', 'pkgver': '3.6.1~20150924-5ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.2-3ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.2-3ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'libdcmtk12', 'pkgver': '3.6.2-3ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.4-2.1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.4-2.1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'libdcmtk14', 'pkgver': '3.6.4-2.1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.6-5ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.6-5ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libdcmtk16', 'pkgver': '3.6.6-5ubuntu0.1~esm1'},
    {'osver': '22.10', 'pkgname': 'dcmtk', 'pkgver': '3.6.7-6ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.7-6ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libdcmtk17', 'pkgver': '3.6.7-6ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dcmtk / libdcmtk-dev / libdcmtk12 / libdcmtk14 / libdcmtk16 / etc');
}
