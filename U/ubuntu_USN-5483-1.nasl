##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5483-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162376);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2018-12648",
    "CVE-2021-36045",
    "CVE-2021-36046",
    "CVE-2021-36047",
    "CVE-2021-36048",
    "CVE-2021-36050",
    "CVE-2021-36051",
    "CVE-2021-36052",
    "CVE-2021-36053",
    "CVE-2021-36054",
    "CVE-2021-36055",
    "CVE-2021-36056",
    "CVE-2021-36058",
    "CVE-2021-36064",
    "CVE-2021-39847",
    "CVE-2021-40716",
    "CVE-2021-40732",
    "CVE-2021-42528",
    "CVE-2021-42529",
    "CVE-2021-42530",
    "CVE-2021-42531",
    "CVE-2021-42532"
  );
  script_xref(name:"USN", value:"5483-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : Exempi vulnerabilities (USN-5483-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5483-1 advisory.

  - The WEBP::GetLE32 function in XMPFiles/source/FormatSupport/WEBP_Support.hpp in Exempi 2.4.5 has a NULL
    pointer dereference. (CVE-2018-12648)

  - XMP Toolkit SDK versions 2020.1 (and earlier) are affected by an out-of-bounds read vulnerability that
    could lead to disclosure of arbitrary memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2021-36045, CVE-2021-36053)

  - XMP Toolkit version 2020.1 (and earlier) is affected by a memory corruption vulnerability, potentially
    resulting in arbitrary code execution in the context of the current user. User interaction is required to
    exploit this vulnerability. (CVE-2021-36046, CVE-2021-36052)

  - XMP Toolkit SDK version 2020.1 (and earlier) is affected by an Improper Input Validation vulnerability
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation
    requires user interaction in that a victim must open a crafted file. (CVE-2021-36047, CVE-2021-36048)

  - XMP Toolkit SDK version 2020.1 (and earlier) is affected by a buffer overflow vulnerability potentially
    resulting in arbitrary code execution in the context of the current user. Exploitation requires user
    interaction in that a victim must open a crafted file. (CVE-2021-36050, CVE-2021-36056)

  - XMP Toolkit SDK version 2020.1 (and earlier) is affected by a buffer overflow vulnerability potentially
    resulting in arbitrary code execution in the context of the current user. Exploitation requires user
    interaction in that a victim must open a specially-crafted .cpp file. (CVE-2021-36051)

  - XMP Toolkit SDK version 2020.1 (and earlier) is affected by a buffer overflow vulnerability potentially
    resulting in local application denial of service in the context of the current user. Exploitation requires
    user interaction in that a victim must open a crafted file. (CVE-2021-36054)

  - XMP Toolkit SDK versions 2020.1 (and earlier) are affected by a use-after-free vulnerability that could
    result in arbitrary code execution in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-36055)

  - XMP Toolkit SDK version 2020.1 (and earlier) is affected by an Integer Overflow vulnerability potentially
    resulting in application-level denial of service in the context of the current user. Exploitation requires
    user interaction in that a victim must open a crafted file. (CVE-2021-36058)

  - XMP Toolkit version 2020.1 (and earlier) is affected by a Buffer Underflow vulnerability which could
    result in arbitrary code execution in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-36064)

  - XMP Toolkit SDK version 2020.1 (and earlier) is affected by a stack-based buffer overflow vulnerability
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation
    requires user interaction in that a victim must open a crafted file. (CVE-2021-39847)

  - XMP Toolkit SDK versions 2021.07 (and earlier) are affected by an out-of-bounds read vulnerability that
    could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2021-40716)

  - XMP Toolkit version 2020.1 (and earlier) is affected by a null pointer dereference vulnerability that
    could result in leaking data from certain memory locations and causing a local denial of service in the
    context of the current user. User interaction is required to exploit this vulnerability in that the victim
    will need to open a specially crafted MXF file. (CVE-2021-40732)

  - XMP Toolkit 2021.07 (and earlier) is affected by a Null pointer dereference vulnerability when parsing a
    specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve an
    application denial-of-service in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-42528)

  - XMP Toolkit SDK version 2021.07 (and earlier) is affected by a stack-based buffer overflow vulnerability
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation
    requires user interaction in that a victim must open a crafted file. (CVE-2021-42529, CVE-2021-42530,
    CVE-2021-42531, CVE-2021-42532)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5483-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42532");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exempi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexempi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexempi3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexempi8");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'exempi', 'pkgver': '2.4.5-2ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libexempi-dev', 'pkgver': '2.4.5-2ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libexempi3', 'pkgver': '2.4.5-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'exempi', 'pkgver': '2.5.1-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libexempi-dev', 'pkgver': '2.5.1-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libexempi8', 'pkgver': '2.5.1-1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'exempi', 'pkgver': '2.5.2-1ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libexempi-dev', 'pkgver': '2.5.2-1ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libexempi8', 'pkgver': '2.5.2-1ubuntu0.21.10.1'},
    {'osver': '22.04', 'pkgname': 'exempi', 'pkgver': '2.5.2-1ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libexempi-dev', 'pkgver': '2.5.2-1ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libexempi8', 'pkgver': '2.5.2-1ubuntu0.22.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exempi / libexempi-dev / libexempi3 / libexempi8');
}
