#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-362-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27942);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-4485", "CVE-2006-4486", "CVE-2006-4625", "CVE-2006-4812");
  script_bugtraq_id(19582, 19933, 20349);
  script_xref(name:"USN", value:"362-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : php4, php5 vulnerabilities (USN-362-1)");
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
"The stripos() function did not check for invalidly long or empty
haystack strings. In an application that uses this function on
arbitrary untrusted data this could be exploited to crash the PHP
interpreter. (CVE-2006-4485)

An integer overflow was discovered in the PHP memory allocation
handling. On 64-bit platforms, the 'memory_limit' setting was not
enforced correctly. A remote attacker could exploit this to cause a
Denial of Service attack through memory exhaustion. (CVE-2006-4486)

Maksymilian Arciemowicz discovered that security relevant
configuration options like open_basedir and safe_mode (which can be
configured in Apache's httpd.conf) could be bypassed and reset to
their default value in php.ini by using the ini_restore() function.
(CVE-2006-4625)

Stefan Esser discovered that the ecalloc() function in the Zend engine
did not check for integer overflows. This particularly affected the
unserialize() function. In applications which unserialize untrusted
user-defined data, this could be exploited to execute arbitrary code
with the application's privileges. (CVE-2006-4812).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/362-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libapache2-mod-php4", pkgver:"4:4.3.10-10ubuntu4.8")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4", pkgver:"4.3.10-10ubuntu4.8")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cgi", pkgver:"4:4.3.10-10ubuntu4.8")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cli", pkgver:"4:4.3.10-10ubuntu4.8")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-common", pkgver:"4.3.10-10ubuntu4.8")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-dev", pkgver:"4.3.10-10ubuntu4.8")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapache2-mod-php5", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php-pear", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cgi", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cli", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-common", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-curl", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-dev", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-gd", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-ldap", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mhash", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mysql", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-odbc", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-pgsql", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-recode", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-snmp", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sqlite", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sybase", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xmlrpc", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xsl", pkgver:"5.0.5-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-ldap", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mhash", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysql", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysqli", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-odbc", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-pgsql", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-recode", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-snmp", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sqlite", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sybase", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xmlrpc", pkgver:"5.1.2-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xsl", pkgver:"5.1.2-1ubuntu3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php4 / libapache2-mod-php5 / php-pear / php4 / etc");
}
