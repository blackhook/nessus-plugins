#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2052-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71374);
  script_version("1.11");
  script_cvs_date("Date: 2019/09/19 12:54:29");

  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5611", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673");
  script_bugtraq_id(63676, 63679, 64203, 64204, 64205, 64206, 64207, 64209, 64210, 64211, 64212, 64213, 64214, 64215, 64216);
  script_xref(name:"USN", value:"2052-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 / 13.10 : firefox vulnerabilities (USN-2052-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ben Turner, Bobby Holley, Jesse Ruderman, Christian Holler and
Christoph Diehl discovered multiple memory safety issues in Firefox.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-5609, CVE-2013-5610)

Myk Melez discovered that the doorhanger notification for web app
installation could persist between page navigations. An attacker could
potentially exploit this to conduct clickjacking attacks.
(CVE-2013-5611)

Masato Kinugawa discovered that pages with missing character set
encoding information can inherit character encodings across
navigations from another domain. An attacker could potentially exploit
this to conduct cross-site scripting attacks. (CVE-2013-5612)

Daniel Veditz discovered that a sandboxed iframe could use an object
element to bypass its own restrictions. (CVE-2013-5614)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
event listeners. An attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2013-5616)

A use-after-free was discovered in the table editing interface. An
attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-5618)

Dan Gohman discovered that binary search algorithms in Spidermonkey
used arithmetic prone to overflow in several places. However, this is
issue not believed to be exploitable. (CVE-2013-5619)

Tyson Smith and Jesse Schwartzentruber discovered a crash when
inserting an ordered list in to a document using script. An attacker
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-6671)

Vincent Lefevre discovered that web content could access clipboard
data under certain circumstances, resulting in information disclosure.
(CVE-2013-6672)

Sijie Xia discovered that trust settings for built-in EV root
certificates were ignored under certain circumstances, removing the
ability for a user to manually untrust certificates from specific
authorities. (CVE-2013-6673)

Tyson Smith, Jesse Schwartzentruber and Atte Kettunen discovered a
use-after-free in functions for synthetic mouse movement handling. An
attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-5613)

Eric Faust discovered that GetElementIC typed array stubs can be
generated outside observed typesets. An attacker could possibly
exploit this to cause undefined behaviour with a potential security
impact. (CVE-2013-5615)

Michal Zalewski discovered several issues with JPEG image handling. An
attacker could potentially exploit these to obtain sensitive
information. (CVE-2013-6629, CVE-2013-6630).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2052-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2019 Canonical, Inc. / NASL script (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(12\.04|12\.10|13\.04|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"26.0+build2-0ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"26.0+build2-0ubuntu0.12.10.2")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"firefox", pkgver:"26.0+build2-0ubuntu0.13.04.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"firefox", pkgver:"26.0+build2-0ubuntu0.13.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
