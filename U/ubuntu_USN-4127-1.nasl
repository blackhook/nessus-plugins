#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4127-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128631);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-20406", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948");
  script_xref(name:"USN", value:"4127-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.04 : python2.7, python3.5, python3.6, python3.7 vulnerabilities (USN-4127-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that Python incorrectly handled certain pickle
files. An attacker could possibly use this issue to consume memory,
leading to a denial of service. This issue only affected Ubuntu 16.04
LTS and Ubuntu 18.04 LTS. (CVE-2018-20406)

It was discovered that Python incorrectly validated the domain when
handling cookies. An attacker could possibly trick Python into sending
cookies to the wrong domain. (CVE-2018-20852)

Jonathan Birch and Panayiotis Panayiotou discovered that Python
incorrectly handled Unicode encoding during NFKC normalization. An
attacker could possibly use this issue to obtain sensitive
information. (CVE-2019-9636, CVE-2019-10160)

Colin Read and Nicolas Edet discovered that Python incorrectly handled
parsing certain X509 certificates. An attacker could possibly use this
issue to cause Python to crash, resulting in a denial of service. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2019-5010)

It was discovered that Python incorrectly handled certain urls. A
remote attacker could possibly use this issue to perform CRLF
injection attacks. (CVE-2019-9740, CVE-2019-9947)

Sihoon Lee discovered that Python incorrectly handled the local_file:
scheme. A remote attacker could possibly use this issue to bypass
blacklist meschanisms. (CVE-2019-9948).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4127-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9948");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"python2.7", pkgver:"2.7.12-1ubuntu0~16.04.8")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python2.7-minimal", pkgver:"2.7.12-1ubuntu0~16.04.8")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3.5", pkgver:"3.5.2-2ubuntu0~16.04.8")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3.5-minimal", pkgver:"3.5.2-2ubuntu0~16.04.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python2.7", pkgver:"2.7.15-4ubuntu4~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python2.7-minimal", pkgver:"2.7.15-4ubuntu4~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python3.6", pkgver:"3.6.8-1~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python3.6-minimal", pkgver:"3.6.8-1~18.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python2.7", pkgver:"2.7.16-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python2.7-minimal", pkgver:"2.7.16-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python3.7", pkgver:"3.7.3-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python3.7-minimal", pkgver:"3.7.3-2ubuntu0.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2.7 / python2.7-minimal / python3.5 / python3.5-minimal / etc");
}
