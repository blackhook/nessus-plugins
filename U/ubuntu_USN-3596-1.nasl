#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3596-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108370);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-5125", "CVE-2018-5126", "CVE-2018-5127", "CVE-2018-5128", "CVE-2018-5129", "CVE-2018-5130", "CVE-2018-5131", "CVE-2018-5132", "CVE-2018-5133", "CVE-2018-5134", "CVE-2018-5135", "CVE-2018-5136", "CVE-2018-5137", "CVE-2018-5140", "CVE-2018-5141", "CVE-2018-5142", "CVE-2018-5143");
  script_xref(name:"USN", value:"3596-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : Firefox vulnerabilities (USN-3596-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash or opening new tabs, escape the sandbox, bypass same-origin
restrictions, obtain sensitive information, confuse the user with
misleading permission requests, or execute arbitrary code.
(CVE-2018-5125, CVE-2018-5126, CVE-2018-5127, CVE-2018-5128,
CVE-2018-5129, CVE-2018-5130, CVE-2018-5136, CVE-2018-5137,
CVE-2018-5140, CVE-2018-5141, CVE-2018-5142)

It was discovered that the fetch() API could incorrectly return cached
copies of no-store/no-cache resources in some circumstances. A local
attacker could potentially exploit this to obtain sensitive
information in environments where multiple users share a common
profile. (CVE-2018-5131)

Multiple security issues were discovered with WebExtensions. If a user
were tricked in to installing a specially crafted extension, an
attacker could potentially exploit these to obtain sensitive
information or bypass security restrictions. (CVE-2018-5132,
CVE-2018-5134, CVE-2018-5135)

It was discovered that the value of app.support.baseURL is not
sanitized properly. If a malicious local application were to set this
to a specially crafted value, an attacker could potentially exploit
this to execute arbitrary code. (CVE-2018-5133)

It was discovered that javascript: URLs with embedded tab characters
could be pasted in to the addressbar. If a user were tricked in to
copying a specially crafted URL in to the addressbar, an attacker
could exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2018-5143).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3596-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/15");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"59.0+build5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"59.0+build5-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"firefox", pkgver:"59.0+build5-0ubuntu0.17.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
