#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1192-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55899);
  script_version("1.8");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2011-0084", "CVE-2011-2985", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2990", "CVE-2011-2991", "CVE-2011-2993");
  script_xref(name:"USN", value:"1192-2");

  script_name(english:"Ubuntu 11.04 : mozvoikko update (USN-1192-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1192-1 fixed vulnerabilities in Firefox. This update provides an
updated Mozvoikko for use with Firefox 6.

Aral Yaman discovered a vulnerability in the WebGL engine. An attacker
could potentially use this to crash Firefox or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2011-2989)

Vivekanand Bolajwar discovered a vulnerability in the
JavaScript engine. An attacker could potentially use this to
crash Firefox or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2011-2991)

Bert Hubert and Theo Snelleman discovered a vulnerability in
the Ogg reader. An attacker could potentially use this to
crash Firefox or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2011-2991)

Robert Kaiser, Jesse Ruderman, Gary Kwong, Christoph Diehl,
Martijn Wargers, Travis Emmitt, Bob Clary, and Jonathan Watt
discovered multiple memory vulnerabilities in the browser
rendering engine. An attacker could use these to possibly
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2985)

Rafael Gieschke discovered that unsigned JavaScript could
call into a script inside a signed JAR. This could allow an
attacker to execute arbitrary code with the identity and
permissions of the signed JAR. (CVE-2011-2993)

Michael Jordon discovered that an overly long shader program
could cause a buffer overrun. An attacker could potentially
use this to crash Firefox or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2011-2988)

Michael Jordon discovered a heap overflow in the ANGLE
library used in Firefox's WebGL implementation. An attacker
could potentially use this to crash Firefox or execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2011-2987)

It was discovered that an SVG text manipulation routine
contained a dangling pointer vulnerability. An attacker
could potentially use this to crash Firefox or execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2011-0084)

Mike Cardwell discovered that Content Security Policy
violation reports failed to strip out proxy authorization
credentials from the list of request headers. This could
allow a malicious website to capture proxy authorization
credentials. Daniel Veditz discovered that redirecting to a
website with Content Security Policy resulted in the
incorrect resolution of hosts in the constructed policy.
This could allow a malicious website to circumvent the
Content Security Policy of another website. (CVE-2011-2990).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1192-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xul-ext-mozvoikko package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-mozvoikko");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-mozvoikko", pkgver:"1.9.0~svn20101114r3591-0ubuntu3.11.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xul-ext-mozvoikko");
}
