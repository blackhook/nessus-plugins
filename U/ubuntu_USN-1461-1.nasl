#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1461-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59385);
  script_version("1.11");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-2143", "CVE-2012-2655");
  script_bugtraq_id(53729);
  script_xref(name:"USN", value:"1461-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : postgresql-8.3, postgresql-8.4, postgresql-9.1 vulnerabilities (USN-1461-1)");
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
"It was discovered that PostgreSQL incorrectly handled certain bytes
passed to the crypt() function when using DES encryption. An attacker
could use this flaw to incorrectly handle authentication.
(CVE-2012-2143)

It was discovered that PostgreSQL incorrectly handled SECURITY DEFINER
and SET attributes on procedural call handlers. An attacker could use
this flaw to cause PostgreSQL to crash, leading to a denial of
service. (CVE-2012-2655).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1461-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected postgresql-8.3, postgresql-8.4 and / or
postgresql-9.1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/06");
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
if (! preg(pattern:"^(8\.04|10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"postgresql-8.3", pkgver:"8.3.19-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-8.4", pkgver:"8.4.12-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"postgresql-8.4", pkgver:"8.4.12-0ubuntu11.04")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"postgresql-9.1", pkgver:"9.1.4-0ubuntu11.10")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"postgresql-9.1", pkgver:"9.1.4-0ubuntu12.04")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql-8.3 / postgresql-8.4 / postgresql-9.1");
}
