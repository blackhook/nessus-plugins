#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1022-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50824);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2010-1623");
  script_bugtraq_id(43673);
  script_xref(name:"USN", value:"1022-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : apr-util vulnerability (USN-1022-1)");
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
"It was discovered that APR-util did not properly handle memory when
destroying APR buckets. An attacker could exploit this and cause a
denial of service via memory exhaustion.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1022-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbd-freetds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbd-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbd-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libaprutil1-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/28");
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

if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1", pkgver:"1.2.12+dfsg-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1-dbg", pkgver:"1.2.12+dfsg-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libaprutil1-dev", pkgver:"1.2.12+dfsg-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-dbd-freetds", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-dbd-mysql", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-dbd-odbc", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-dbd-pgsql", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-dbd-sqlite3", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-dbg", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-dev", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libaprutil1-ldap", pkgver:"1.3.9+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-dbd-freetds", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-dbd-mysql", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-dbd-odbc", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-dbd-pgsql", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-dbd-sqlite3", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-dbg", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-dev", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libaprutil1-ldap", pkgver:"1.3.9+dfsg-3ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-dbd-freetds", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-dbd-mysql", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-dbd-odbc", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-dbd-pgsql", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-dbd-sqlite3", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-dbg", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-dev", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libaprutil1-ldap", pkgver:"1.3.9+dfsg-3ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libaprutil1 / libaprutil1-dbd-freetds / libaprutil1-dbd-mysql / etc");
}
