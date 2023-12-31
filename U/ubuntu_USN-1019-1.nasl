#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1019-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51114);
  script_version("1.13");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778");
  script_bugtraq_id(45314, 45322);
  script_xref(name:"USN", value:"1019-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : firefox, firefox-{3.0,3.5}, xulrunner-1.9.{1,2} vulnerabilities (USN-1019-1)");
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
"Jesse Ruderman, Andreas Gal, Nils, Brian Hackett, and Igor Bukanov
discovered several memory issues in the browser engine. An attacker
could exploit these to crash the browser or possibly run arbitrary
code as the user invoking the program. (CVE-2010-3776, CVE-2010-3777,
CVE-2010-3778)

It was discovered that Firefox did not properly verify the about:blank
location elements when it was opened via window.open(). An attacker
could exploit this to run arbitrary code with chrome privileges.
(CVE-2010-3771)

It was discovered that Firefox did not properly handle &lt;div&gt;
elements when processing a XUL tree. If a user were tricked into
opening a malicious web page, an attacker could exploit this to crash
the browser or possibly run arbitrary code as the user invoking the
program. (CVE-2010-3772)

Marc Schoenefeld and Christoph Diehl discovered several problems when
handling downloadable fonts. The new OTS font sanitizing library was
added to mitigate these issues. (CVE-2010-3768)

Gregory Fleischer discovered that the Java LiveConnect script could be
made to run in the wrong security context. An attacker could exploit
this to read local files and run arbitrary code as the user invoking
the program. (CVE-2010-3775)

Several problems were discovered in the JavaScript engine. If a user
were tricked into opening a malicious web page, an attacker could
exploit this to crash the browser or possibly run arbitrary code as
the user invoking the program. (CVE-2010-3766, CVE-2010-3767,
CVE-2010-3773)

Michal Zalewski discovered that Firefox did not always properly handle
displaying pages from network or certificate errors. An attacker could
exploit this to spoof the location bar, such as in a phishing attack.
(CVE-2010-3774)

Yosuke Hasegawa and Masatoshi Kimura discovered that several character
encodings would have some characters converted to angle brackets. An
attacker could utilize this to perform cross-site scripting attacks.
(CVE-2010-3770).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1019-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-testsuite-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-testsuite-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2019 Canonical, Inc. / NASL script (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"abrowser", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"abrowser-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-libthai", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-dom-inspector", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-libthai", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-venkman", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dom-inspector", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1", pkgver:"1.9.1.16+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-dbg", pkgver:"1.9.1.16+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-dev", pkgver:"1.9.1.16+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-gnome-support", pkgver:"1.9.1.16+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-testsuite", pkgver:"1.9.1.16+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-testsuite-dev", pkgver:"1.9.1.16+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser-3.5", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser-3.5-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-dom-inspector", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-libthai", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.0", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.0-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-dev", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-mozsymbols", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"abrowser", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"abrowser-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-branding", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-gnome-support", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-mozsymbols", pkgver:"3.6.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-dev", pkgver:"1.9.2.13+build3+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrowser / abrowser-3.0 / abrowser-3.0-branding / abrowser-3.1 / etc");
}
