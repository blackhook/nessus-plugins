#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1400-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58589);
  script_version("1.8");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0464");
  script_xref(name:"USN", value:"1400-4");

  script_name(english:"Ubuntu 11.10 : thunderbird regressions (USN-1400-4)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1400-3 fixed vulnerabilities in Thunderbird. The new Thunderbird
version caused a regression in IMAP connections and mail filtering.
This update fixes the problem.

Soroush Dalili discovered that Firefox did not adequately protect
against dropping JavaScript links onto a frame. A remote attacker
could, through cross-site scripting (XSS), exploit this to modify the
contents or steal confidential data. (CVE-2012-0455)

Atte Kettunen discovered a use-after-free vulnerability in
Firefox's handling of SVG animations. An attacker could
potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2012-0457)

Atte Kettunen discovered an out of bounds read vulnerability
in Firefox's handling of SVG Filters. An attacker could
potentially exploit this to make data from the user's memory
accessible to the page content. (CVE-2012-0456)

Mike Brooks discovered that using carriage return line feed
(CRLF) injection, one could introduce a new Content Security
Policy (CSP) rule which allows for cross-site scripting
(XSS) on sites with a separate header injection
vulnerability. With cross-site scripting vulnerabilities, if
a user were tricked into viewing a specially crafted page, a
remote attacker could exploit this to modify the contents,
or steal confidential data, within the same domain.
(CVE-2012-0451)

Mariusz Mlynski discovered that the Home button accepted
JavaScript links to set the browser Home page. An attacker
could use this vulnerability to get the script URL loaded in
the privileged about:sessionrestore context. (CVE-2012-0458)

Daniel Glazman discovered that the Cascading Style Sheets
(CSS) implementation is vulnerable to crashing due to
modification of a keyframe followed by access to the cssText
of the keyframe. If the user were tricked into opening a
specially crafted web page, an attacker could exploit this
to cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Firefox. (CVE-2012-0459)

Matt Brubeck discovered that Firefox did not properly
restrict access to the window.fullScreen object. If the user
were tricked into opening a specially crafted web page, an
attacker could potentially use this vulnerability to spoof
the user interface. (CVE-2012-0460)

Bob Clary, Christian Holler, Jesse Ruderman, Michael
Bebenita, David Anderson, Jeff Walden, Vincenzo Iozzo, and
Willem Pinckaers discovered memory safety issues affecting
Firefox. If the user were tricked into opening a specially
crafted page, an attacker could exploit these to cause a
denial of service via application crash, or potentially
execute code with the privileges of the user invoking
Firefox. (CVE-2012-0461, CVE-2012-0462, CVE-2012-0464).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1400-4/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");
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
if (! preg(pattern:"^(11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.10", pkgname:"thunderbird", pkgver:"11.0.1+build1-0ubuntu0.11.10.1")) flag++;

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
