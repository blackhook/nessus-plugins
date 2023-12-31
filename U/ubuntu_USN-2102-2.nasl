#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2102-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72598);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1489", "CVE-2014-1490", "CVE-2014-1491");
  script_bugtraq_id(65316, 65320, 65321, 65322, 65326, 65328, 65329, 65330, 65331, 65332, 65334, 65335);
  script_xref(name:"USN", value:"2102-2");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : firefox regression (USN-2102-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2102-1 fixed vulnerabilities in Firefox. The update introduced a
regression which could make Firefox crash under some circumstances.
This update fixes the problem.

We apologize for the inconvenience.

Christian Holler, Terrence Cole, Jesse Ruderman, Gary Kwong, Eric
Rescorla, Jonathan Kew, Dan Gohman, Ryan VanderMeulen, Carsten Book,
Andrew Sutherland, Byron Campen, Nicholas Nethercote, Paul Adenot,
David Baron, Julian Seward and Sotaro Ikeda discovered multiple memory
safety issues in Firefox. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1477, CVE-2014-1478)

Cody Crews discovered a method to bypass System Only
Wrappers. An attacker could potentially exploit this to
steal confidential data or execute code with the privileges
of the user invoking Firefox. (CVE-2014-1479)

Jordi Chancel discovered that the downloads dialog did not
implement a security timeout before button presses are
processed. An attacker could potentially exploit this to
conduct clickjacking attacks. (CVE-2014-1480)

Fredrik Lonnqvist discovered a use-after-free in Firefox.
An attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code
with the priviliges of the user invoking Firefox.
(CVE-2014-1482)

Jordan Milne discovered a timing flaw when using
document.elementFromPoint and
document.caretPositionFromPoint on cross-origin iframes. An
attacker could potentially exploit this to steal
confidential imformation. (CVE-2014-1483)

Frederik Braun discovered that the CSP implementation in
Firefox did not handle XSLT stylesheets in accordance with
the specification, potentially resulting in unexpected
script execution in some circumstances (CVE-2014-1485)

Arthur Gerkis discovered a use-after-free in Firefox. An
attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code
with the priviliges of the user invoking Firefox.
(CVE-2014-1486)

Masato Kinugawa discovered a cross-origin information leak
in web worker error messages. An attacker could potentially
exploit this to steal confidential information.
(CVE-2014-1487)

Yazan Tommalieh discovered that web pages could activate
buttons on the default Firefox startpage (about:home) in
some circumstances. An attacker could potentially exploit
this to cause data loss by triggering a session restore.
(CVE-2014-1489)

Soeren Balko discovered a crash in Firefox when terminating
web workers running asm.js code in some circumstances. An
attacker could potentially exploit this to execute arbitrary
code with the priviliges of the user invoking Firefox.
(CVE-2014-1488)

Several issues were discovered with ticket handling in NSS.
An attacker could potentially exploit these to cause a
denial of service or bypass cryptographic protection
mechanisms. (CVE-2014-1490, CVE-2014-1491)

Boris Zbarsky discovered that security restrictions on
window objects could be bypassed under certain
circumstances. (CVE-2014-1481).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2102-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"27.0.1+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"27.0.1+build1-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"firefox", pkgver:"27.0.1+build1-0ubuntu0.13.10.1")) flag++;

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
