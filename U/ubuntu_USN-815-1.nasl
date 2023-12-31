#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-815-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40576);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-3529", "CVE-2009-2414", "CVE-2009-2416");
  script_bugtraq_id(31126, 36010);
  script_xref(name:"USN", value:"815-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : libxml2 vulnerabilities (USN-815-1)");
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
"It was discovered that libxml2 did not correctly handle root XML
document element DTD definitions. If a user were tricked into
processing a specially crafted XML document, a remote attacker could
cause the application linked against libxml2 to crash, leading to a
denial of service. (CVE-2009-2414)

It was discovered that libxml2 did not correctly parse Notation and
Enumeration attribute types. If a user were tricked into processing a
specially crafted XML document, a remote attacker could cause the
application linked against libxml2 to crash, leading to a denial of
service. (CVE-2009-2416)

USN-644-1 fixed a vulnerability in libxml2. This advisory provides the
corresponding update for Ubuntu 9.04.

It was discovered that libxml2 did not correctly handle long entity
names. If a user were tricked into processing a specially crafted XML
document, a remote attacker could execute arbitrary code with user
privileges or cause the application linked against libxml2 to crash,
leading to a denial of service. (CVE-2008-3529).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/815-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2019 Canonical, Inc. / NASL script (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-dbg", pkgver:"2.6.24.dfsg-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-dev", pkgver:"2.6.24.dfsg-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-doc", pkgver:"2.6.24.dfsg-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-utils", pkgver:"2.6.24.dfsg-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2", pkgver:"2.6.31.dfsg-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-dbg", pkgver:"2.6.31.dfsg-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-dev", pkgver:"2.6.31.dfsg-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-doc", pkgver:"2.6.31.dfsg-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-utils", pkgver:"2.6.31.dfsg-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxml2", pkgver:"2.6.31.dfsg-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxml2-dbg", pkgver:"2.6.31.dfsg-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxml2", pkgver:"2.6.32.dfsg-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxml2-dbg", pkgver:"2.6.32.dfsg-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxml2-dev", pkgver:"2.6.32.dfsg-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxml2-doc", pkgver:"2.6.32.dfsg-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxml2-utils", pkgver:"2.6.32.dfsg-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-libxml2", pkgver:"2.6.32.dfsg-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-libxml2-dbg", pkgver:"2.6.32.dfsg-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libxml2", pkgver:"2.6.32.dfsg-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libxml2-dbg", pkgver:"2.6.32.dfsg-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libxml2-dev", pkgver:"2.6.32.dfsg-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libxml2-doc", pkgver:"2.6.32.dfsg-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libxml2-utils", pkgver:"2.6.32.dfsg-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-libxml2", pkgver:"2.6.32.dfsg-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-libxml2-dbg", pkgver:"2.6.32.dfsg-5ubuntu4.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-dbg / libxml2-dev / libxml2-doc / libxml2-utils / etc");
}
