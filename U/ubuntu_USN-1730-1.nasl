#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1730-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64782);
  script_version("1.11");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2013-0282", "CVE-2013-1664", "CVE-2013-1665");
  script_xref(name:"USN", value:"1730-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 : keystone vulnerabilities (USN-1730-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nathanael Burton discovered that Keystone did not properly verify
disabled users. An authenticated but disabled user would continue to
have access rights that were removed. (CVE-2013-0282)

Jonathan Murray discovered that Keystone would allow XML entity
processing. A remote unauthenticated attacker could exploit this to
cause a denial of service via resource exhaustion. Authenticated users
could also use this to view arbitrary files on the Keystone server.
(CVE-2013-1664, CVE-2013-1665).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1730-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-keystone package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-keystone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
if (! preg(pattern:"^(12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"python-keystone", pkgver:"2012.1+stable~20120824-a16a0ab9-0ubuntu2.5")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python-keystone", pkgver:"2012.2.1-0ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-keystone");
}
