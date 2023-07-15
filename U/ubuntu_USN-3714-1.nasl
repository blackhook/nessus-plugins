#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3714-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111060);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12372", "CVE-2018-12373", "CVE-2018-12374", "CVE-2018-5188");
  script_xref(name:"USN", value:"3714-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 / 18.04 LTS : Thunderbird vulnerabilities (USN-3714-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in Thunderbird. If a user
were tricked in to opening a specially crafted website in a browsing
context, an attacker could potentially exploit these to cause a denial
of service, bypass CORS restrictions, obtain sensitive information, or
execute arbitrary code. (CVE-2018-12359, CVE-2018-12360,
CVE-2018-12362, CVE-2018-12363, CVE-2018-12364, CVE-2018-12365,
CVE-2018-12366)

It was discovered that S/MIME and PGP decryption oracles can be built
with HTML emails. An attacker could potentially exploit this to obtain
sensitive information. (CVE-2018-12372)

It was discovered that S/MIME plaintext can be leaked through HTML
reply/forward. An attacker could potentially exploit this to obtain
sensitive information. (CVE-2018-12373)

It was discovered that forms can be used to exfiltrate encrypted mail
parts by pressing enter in a form field. An attacker could potentially
exploit this to obtain sensitive information. (CVE-2018-12374).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3714-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.10|18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10 / 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"thunderbird", pkgver:"1:52.9.1+build3-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"thunderbird", pkgver:"1:52.9.1+build3-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"thunderbird", pkgver:"1:52.9.1+build3-0ubuntu0.17.10.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"thunderbird", pkgver:"1:52.9.1+build3-0ubuntu0.18.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
