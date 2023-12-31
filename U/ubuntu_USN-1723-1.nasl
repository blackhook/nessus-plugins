#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1723-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64638);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-5624", "CVE-2012-6093", "CVE-2013-0254");
  script_bugtraq_id(56807, 57162, 57772);
  script_xref(name:"USN", value:"1723-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : qt4-x11 vulnerabilities (USN-1723-1)");
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
"Richard J. Moore and Peter Hartmann discovered that Qt allowed
redirecting requests from http to file schemes. If an attacker were
able to perform a man-in-the-middle attack, this flaw could be
exploited to view sensitive information. This issue only affected
Ubuntu 11.10, Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2012-5624)

Stephen Cheng discovered that Qt may report incorrect errors when ssl
certificate verification fails. (CVE-2012-6093)

Tim Brown and Mark Lowe discovered that Qt incorrectly used weak
permissions on shared memory segments. A local attacker could use this
issue to view sensitive information, or modify program data belonging
to other users. (CVE-2013-0254).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1723-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libqt4-core and / or libqt4-network packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-network");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/15");
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
if (! preg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libqt4-core", pkgver:"4:4.6.2-0ubuntu5.6")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-network", pkgver:"4:4.6.2-0ubuntu5.6")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libqt4-core", pkgver:"4:4.7.4-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libqt4-network", pkgver:"4:4.7.4-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libqt4-core", pkgver:"4:4.8.1-0ubuntu4.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libqt4-network", pkgver:"4:4.8.1-0ubuntu4.4")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libqt4-core", pkgver:"4:4.8.3+dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libqt4-network", pkgver:"4:4.8.3+dfsg-0ubuntu3.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt4-core / libqt4-network");
}
