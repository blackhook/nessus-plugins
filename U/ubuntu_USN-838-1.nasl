#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-838-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(41940);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-4577", "CVE-2008-5301", "CVE-2009-2632", "CVE-2009-3235");
  script_bugtraq_id(31587, 36377);
  script_xref(name:"USN", value:"838-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : dovecot vulnerabilities (USN-838-1)");
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
"It was discovered that the ACL plugin in Dovecot would incorrectly
handle negative access rights. An attacker could exploit this flaw to
access the Dovecot server, bypassing the intended access restrictions.
This only affected Ubuntu 8.04 LTS. (CVE-2008-4577)

It was discovered that the ManageSieve service in Dovecot incorrectly
handled '..' in script names. A remote attacker could exploit this to
read and modify arbitrary sieve files on the server. This only
affected Ubuntu 8.10. (CVE-2008-5301)

It was discovered that the Sieve plugin in Dovecot incorrectly handled
certain sieve scripts. An authenticated user could exploit this with a
crafted sieve script to cause a denial of service or possibly execute
arbitrary code. (CVE-2009-2632, CVE-2009-3235).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/838-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/29");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"dovecot-common", pkgver:"1:1.0.10-1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dovecot-dev", pkgver:"1.0.10-1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dovecot-imapd", pkgver:"1.0.10-1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dovecot-pop3d", pkgver:"1.0.10-1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dovecot-common", pkgver:"1:1.1.4-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dovecot-dev", pkgver:"1.1.4-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dovecot-imapd", pkgver:"1.1.4-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dovecot-pop3d", pkgver:"1.1.4-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dovecot-common", pkgver:"1:1.1.11-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dovecot-dev", pkgver:"1.1.11-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dovecot-imapd", pkgver:"1.1.11-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dovecot-pop3d", pkgver:"1.1.11-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dovecot-postfix", pkgver:"1.1.11-0ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot-common / dovecot-dev / dovecot-imapd / dovecot-pop3d / etc");
}
