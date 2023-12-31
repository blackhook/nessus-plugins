#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1951-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69947);
  script_version("1.14");
  script_cvs_date("Date: 2019/09/19 12:54:29");

  script_cve_id("CVE-2013-1718", "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1721", "CVE-2013-1722", "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1728", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-1738");
  script_bugtraq_id(62466);
  script_xref(name:"USN", value:"1951-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : firefox vulnerabilities (USN-1951-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple memory safety issues were discovered in Firefox. If a user
were tricked in to opening a specially crafted page, an attacker could
possibly exploit these to cause a denial of service via application
crash, or potentially execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2013-1718, CVE-2013-1719)

Atte Kettunen discovered a flaw in the HTML5 Tree Builder when
interacting with template elements. In some circumstances, an attacker
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1720)

Alex Chapman discovered an integer overflow vulnerability in the ANGLE
library. An attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-1721)

Abhishek Arya discovered a use-after-free in the Animation Manager. An
attacked could potentially exploit this to execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2013-1722)

Scott Bell discovered a use-after-free when using a select element. An
attacker could potentially exploit this to execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2013-1724)

It was discovered that the scope of new JavaScript objects could be
accessed before their compartment is initialized. An attacker could
potentially exploit this to execute code with the privileges of the
user invoking Firefox. (CVE-2013-1725)

Dan Gohman discovered that some variables and data were used in
IonMonkey, without being initialized, which could lead to information
leakage. (CVE-2013-1728)

Sachin Shinde discovered a crash when moving some XBL-backed nodes in
to a document created by document.open(). An attacker could
potentially exploit this to cause a denial of service. (CVE-2013-1730)

Aki Helin discovered a buffer overflow when combining lists, floats
and multiple columns. An attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-1732)

Two memory corruption bugs when scrolling were discovered. An attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2013-1735, CVE-2013-1736)

Boris Zbarsky discovered that user-defined getters on DOM proxies
would use the expando object as 'this'. An attacker could potentially
exploit this by tricking add-on code in to making incorrect security
sensitive decisions based on malicious values. (CVE-2013-1737)

A use-after-free bug was discovered in Firefox. An attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-1738).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1951-1/"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");
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
if (! preg(pattern:"^(12\.04|12\.10|13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"24.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"24.0+build1-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"firefox", pkgver:"24.0+build1-0ubuntu0.13.04.1")) flag++;

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
