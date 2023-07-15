#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2185-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73786);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-1492", "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1528", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_bugtraq_id(66356, 67123, 67125, 67127, 67129, 67130, 67131, 67132, 67133, 67134, 67135, 67136, 67137);
  script_xref(name:"USN", value:"2185-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 / 14.04 LTS : firefox vulnerabilities (USN-2185-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Bobby Holley, Carsten Book, Christoph Diehl, Gary Kwong, Jan de Mooij,
Jesse Ruderman, Nathan Froyd, John Schoenick, Karl Tomlinson, Vladimir
Vukicevic and Christian Holler discovered multiple memory safety
issues in Firefox. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2014-1518,
CVE-2014-1519)

An out of bounds read was discovered in Web Audio. An attacker could
potentially exploit this cause a denial of service via application
crash or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2014-1522)

Abhishek Arya discovered an out of bounds read when decoding JPG
images. An attacker could potentially exploit this to cause a denial
of service via application crash. (CVE-2014-1523)

Abhishek Arya discovered a buffer overflow when a script uses a
non-XBL object as an XBL object. An attacker could potentially exploit
this to execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2014-1524)

Abhishek Arya discovered a use-after-free in the Text Track Manager
when processing HTML video. An attacker could potentially exploit this
to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1525)

Jukka Jylanki discovered an out-of-bounds write in Cairo when working
with canvas in some circumstances. An attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1528)

Mariusz Mlynski discovered that sites with notification permissions
can run script in a privileged context in some circumstances. An
attacker could exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1529)

It was discovered that browser history navigations could be used to
load a site with the addressbar displaying the wrong address. An
attacker could potentially exploit this to conduct cross-site
scripting or phishing attacks. (CVE-2014-1530)

A use-after-free was discovered when resizing images in some
circumstances. An attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1531)

Christian Heimes discovered that NSS did not handle IDNA domain
prefixes correctly for wildcard certificates. An attacker could
potentially exploit this by using a specially crafted certificate to
conduct a man-in-the-middle attack. (CVE-2014-1492)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free
during host resolution in some circumstances. An attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2014-1532)

Boris Zbarsky discovered that the debugger bypassed XrayWrappers for
some objects. If a user were tricked in to opening a specially crafted
website whilst using the debugger, an attacker could potentially
exploit this to execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2014-1526).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2185-1/"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2021 Canonical, Inc. / NASL script (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.04|12\.10|13\.10|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"29.0+build1-0ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"29.0+build1-0ubuntu0.12.10.3")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"firefox", pkgver:"29.0+build1-0ubuntu0.13.10.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"29.0+build1-0ubuntu0.14.04.2")) flag++;

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
