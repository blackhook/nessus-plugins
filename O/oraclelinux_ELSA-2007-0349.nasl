#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0349 and 
# Oracle Linux Security Advisory ELSA-2007-0349 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67497);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-1864", "CVE-2007-2509");
  script_bugtraq_id(23813);
  script_xref(name:"RHSA", value:"2007:0349");

  script_name(english:"Oracle Linux 4 : php (ELSA-2007-0349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0349 :

Updated PHP packages that fix two security issues are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A heap buffer overflow flaw was found in the PHP 'xmlrpc' extension. A
PHP script which implements an XML-RPC server using this extension
could allow a remote attacker to execute arbitrary code as the
'apache' user. Note that this flaw does not affect PHP applications
using the pure-PHP XML_RPC class provided in /usr/share/pear.
(CVE-2007-1864)

A flaw was found in the PHP 'ftp' extension. If a PHP script used this
extension to provide access to a private FTP server, and passed
untrusted script input directly to any function provided by this
extension, a remote attacker would be able to send arbitrary FTP
commands to the server. (CVE-2007-2509)

Users of PHP should upgrade to these updated packages which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000128.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-devel-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-devel-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-domxml-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-domxml-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-gd-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-gd-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-imap-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-imap-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-ldap-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-ldap-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-mbstring-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-mbstring-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-mysql-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-mysql-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-ncurses-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-ncurses-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-odbc-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-odbc-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-pear-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-pear-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-pgsql-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-pgsql-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-snmp-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-snmp-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-xmlrpc-4.3.9-3.22.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-xmlrpc-4.3.9-3.22.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-domxml / php-gd / php-imap / php-ldap / etc");
}
