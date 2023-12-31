#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1510-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60014);
  script_version("1.15");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1967");
  script_bugtraq_id(54572, 54573, 54574, 54575, 54576, 54578, 54580, 54583, 54584, 54586);
  script_xref(name:"USN", value:"1510-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : thunderbird vulnerabilities (USN-1510-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Benoit Jacob, Jesse Ruderman, Christian Holler, Bill McCloskey, Brian
Smith, Gary Kwong, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle
Huey discovered memory safety issues affecting Thunderbird. If the
user were tricked into opening a specially crafted page, an attacker
could possibly exploit these to cause a denial of service via
application crash, or potentially execute code with the privileges of
the user invoking Thunderbird. (CVE-2012-1948, CVE-2012-1949)

Abhishek Arya discovered four memory safety issues affecting
Thunderbird. If the user were tricked into opening a specially crafted
page, an attacker could possibly exploit these to cause a denial of
service via application crash, or potentially execute code with the
privileges of the user invoking Thunderbird. (CVE-2012-1951,
CVE-2012-1952, CVE-2012-1953, CVE-2012-1954)

Mariusz Mlynski discovered that the address bar may be incorrectly
updated. Calls to history.forward and history.back could be used to
navigate to a site while the address bar still displayed the previous
site. A remote attacker could exploit this to conduct phishing
attacks. (CVE-2012-1955)

Mario Heiderich discovered that HTML <embed> tags were not filtered
out of the HTML <description> of RSS feeds. A remote attacker could
exploit this to conduct cross-site scripting (XSS) attacks via
JavaScript execution in the HTML feed view. (CVE-2012-1957)

Arthur Gerkis discovered a use-after-free vulnerability. If the user
were tricked into opening a specially crafted page, an attacker could
possibly exploit this to cause a denial of service via application
crash, or potentially execute code with the privileges of the user
invoking Thunderbird. (CVE-2012-1958)

Bobby Holley discovered that same-compartment security wrappers (SCSW)
could be bypassed to allow XBL access. If the user were tricked into
opening a specially crafted page, an attacker could possibly exploit
this to execute code with the privileges of the user invoking
Thunderbird. (CVE-2012-1959)

Tony Payne discovered an out-of-bounds memory read in Mozilla's color
management library (QCMS). If the user were tricked into opening a
specially crafted color profile, an attacker could possibly exploit
this to cause a denial of service via application crash.
(CVE-2012-1960)

Frederic Buclin discovered that the X-Frame-Options header was
ignored when its value was specified multiple times. An attacker could
exploit this to conduct clickjacking attacks. (CVE-2012-1961)

Bill Keese discovered a memory corruption vulnerability. If the user
were tricked into opening a specially crafted page, an attacker could
possibly exploit this to cause a denial of service via application
crash, or potentially execute code with the privileges of the user
invoking Thunderbird. (CVE-2012-1962)

Karthikeyan Bhargavan discovered an information leakage vulnerability
in the Content Security Policy (CSP) 1.0 implementation. If the user
were tricked into opening a specially crafted page, an attacker could
possibly exploit this to access a user's OAuth 2.0 access tokens and
OpenID credentials. (CVE-2012-1963)

It was discovered that the execution of javascript: URLs was not
properly handled in some cases. A remote attacker could exploit this
to execute code with the privileges of the user invoking Thunderbird.
(CVE-2012-1967).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1510-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2019 Canonical, Inc. / NASL script (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"14.0+build1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"thunderbird", pkgver:"14.0+build1-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"thunderbird", pkgver:"14.0+build1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"14.0+build1-0ubuntu0.12.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
