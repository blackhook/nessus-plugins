#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1140-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55103);
  script_version("1.8");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2009-0887", "CVE-2010-3316", "CVE-2010-3430", "CVE-2010-3431", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-4706", "CVE-2010-4707");
  script_xref(name:"USN", value:"1140-2");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 : pam regression (USN-1140-2)");
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
"USN-1140-1 fixed vulnerabilities in PAM. A regression was found that
caused cron to stop working with a 'Module is unknown' error. As a
result, systems configured with automatic updates will not receive
updates until cron is restarted, these updates are installed or the
system is rebooted. This update fixes the problem.

We apologize for the inconvenience.

Marcus Granado discovered that PAM incorrectly handled configuration
files with non-ASCII usernames. A remote attacker could use this flaw
to cause a denial of service, or possibly obtain login access with a
different users username. This issue only affected Ubuntu 8.04 LTS.
(CVE-2009-0887)

It was discovered that the PAM pam_xauth, pam_env and
pam_mail modules incorrectly handled dropping privileges
when performing operations. A local attacker could use this
flaw to read certain arbitrary files, and access other
sensitive information. (CVE-2010-3316, CVE-2010-3430,
CVE-2010-3431, CVE-2010-3435)

It was discovered that the PAM pam_namespace module
incorrectly cleaned the environment during execution of the
namespace.init script. A local attacker could use this flaw
to possibly gain privileges. (CVE-2010-3853)

It was discovered that the PAM pam_xauth module incorrectly
handled certain failures. A local attacker could use this
flaw to delete certain unintended files. (CVE-2010-4706)

It was discovered that the PAM pam_xauth module incorrectly
verified certain file properties. A local attacker could use
this flaw to cause a denial of service. (CVE-2010-4707).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1140-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpam-modules and / or libpam0g packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam0g");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(8\.04|10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libpam-modules", pkgver:"0.99.7.1-5ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpam0g", pkgver:"0.99.7.1-5ubuntu6.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpam-modules", pkgver:"1.1.1-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpam0g", pkgver:"1.1.1-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpam-modules", pkgver:"1.1.1-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpam0g", pkgver:"1.1.1-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libpam-modules", pkgver:"1.1.2-2ubuntu8.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libpam0g", pkgver:"1.1.2-2ubuntu8.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-modules / libpam0g");
}
