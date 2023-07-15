#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3544-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106790);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-5089", "CVE-2018-5090", "CVE-2018-5091", "CVE-2018-5092", "CVE-2018-5093", "CVE-2018-5094", "CVE-2018-5095", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5100", "CVE-2018-5101", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5105", "CVE-2018-5106", "CVE-2018-5107", "CVE-2018-5108", "CVE-2018-5109", "CVE-2018-5111", "CVE-2018-5112", "CVE-2018-5113", "CVE-2018-5114", "CVE-2018-5115", "CVE-2018-5116", "CVE-2018-5117", "CVE-2018-5118", "CVE-2018-5119", "CVE-2018-5122");
  script_xref(name:"USN", value:"3544-2");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : firefox regressions (USN-3544-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"USN-3544-1 fixed vulnerabilities in Firefox. The update caused a web
compatibility regression and a tab crash during printing in some
circumstances. This update fixes the problem.

We apologize for the inconvenience.

Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, spoof the origin in audio capture prompts, trick the user in to
providing HTTP credentials for another origin, spoof the addressbar
contents, or execute arbitrary code. (CVE-2018-5089, CVE-2018-5090,
CVE-2018-5091, CVE-2018-5092, CVE-2018-5093, CVE-2018-5094,
CVE-2018-5095, CVE-2018-5097, CVE-2018-5098, CVE-2018-5099,
CVE-2018-5100, CVE-2018-5101, CVE-2018-5102, CVE-2018-5103,
CVE-2018-5104, CVE-2018-5109, CVE-2018-5114, CVE-2018-5115,
CVE-2018-5117, CVE-2018-5122)

Multiple security issues were discovered in WebExtensions.
If a user were tricked in to installing a specially crafted
extension, an attacker could potentially exploit these to
gain additional privileges, bypass same-origin restrictions,
or execute arbitrary code. (CVE-2018-5105, CVE-2018-5113,
CVE-2018-5116)

A security issue was discovered with the developer tools. If
a user were tricked in to opening a specially crafted
website with the developer tools open, an attacker could
potentially exploit this to obtain sensitive information
from other origins. (CVE-2018-5106)

A security issue was discovered with printing. An attacker
could potentially exploit this to obtain sensitive
information from local files. (CVE-2018-5107)

It was discovered that manually entered blob URLs could be
accessed by subsequent private browsing tabs. If a user were
tricked in to entering a blob URL, an attacker could
potentially exploit this to obtain sensitive information
from a private browsing context. (CVE-2018-5108)

It was discovered that dragging certain specially formatted
URLs to the addressbar could cause the wrong URL to be
displayed. If a user were tricked in to opening a specially
crafted website and dragging a URL to the addressbar, an
attacker could potentially exploit this to spoof the
addressbar contents. (CVE-2018-5111)

It was discovered that WebExtension developer tools panels
could open non-relative URLs. If a user were tricked in to
installing a specially crafted extension and running the
developer tools, an attacker could potentially exploit this
to gain additional privileges. (CVE-2018-5112)

It was discovered that ActivityStream images can attempt to
load local content through file: URLs. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this in combination with
another vulnerability that allowed sandbox protections to be
bypassed, in order to obtain sensitive information from
local files. (CVE-2018-5118)

It was discovered that the reader view will load
cross-origin content in violation of CORS headers. An
attacker could exploit this to bypass CORS restrictions.
(CVE-2018-5119).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3544-2/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/13");
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

if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"58.0.2+build1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"58.0.2+build1-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"firefox", pkgver:"58.0.2+build1-0ubuntu0.17.10.1")) flag++;

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
