#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-642-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36904);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-3889");
  script_bugtraq_id(30977);
  script_xref(name:"USN", value:"642-1");

  script_name(english:"Ubuntu 7.10 / 8.04 LTS : postfix vulnerability (USN-642-1)");
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
"Wietse Venema discovered that Postfix leaked internal file descriptors
when executing non-Postfix commands. A local attacker could exploit
this to cause Postfix to run out of descriptors, leading to a denial
of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/642-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-cdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"postfix", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"postfix-cdb", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"postfix-dev", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"postfix-doc", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"postfix-ldap", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"postfix-mysql", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"postfix-pcre", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"postfix-pgsql", pkgver:"2.4.5-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix", pkgver:"2.5.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix-cdb", pkgver:"2.5.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix-dev", pkgver:"2.5.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix-doc", pkgver:"2.5.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix-ldap", pkgver:"2.5.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix-mysql", pkgver:"2.5.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix-pcre", pkgver:"2.5.1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postfix-pgsql", pkgver:"2.5.1-2ubuntu1.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postfix / postfix-cdb / postfix-dev / postfix-doc / postfix-ldap / etc");
}