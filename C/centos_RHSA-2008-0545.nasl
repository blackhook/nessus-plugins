#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0545 and 
# CentOS Errata and Security Advisory 2008:0545 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43693);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-4782", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108");
  script_bugtraq_id(26403, 29009);
  script_xref(name:"RHSA", value:"2008:0545");

  script_name(english:"CentOS 4 : php (CESA-2008:0545)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix several security issues and a bug are
now available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

It was discovered that the PHP escapeshellcmd() function did not
properly escape multi-byte characters which are not valid in the
locale used by the script. This could allow an attacker to bypass
quoting restrictions imposed by escapeshellcmd() and execute arbitrary
commands if the PHP script was using certain locales. Scripts using
the default UTF-8 locale are not affected by this issue.
(CVE-2008-2051)

The PHP functions htmlentities() and htmlspecialchars() did not
properly recognize partial multi-byte sequences. Certain sequences of
bytes could be passed through these functions without being correctly
HTML-escaped. Depending on the browser being used, an attacker could
use this flaw to conduct cross-site scripting attacks. (CVE-2007-5898)

A PHP script which used the transparent session ID configuration
option, or which used the output_add_rewrite_var() function, could
leak session identifiers to external websites. If a page included an
HTML form with an ACTION attribute referencing a non-local URL, the
user's session ID would be included in the form data passed to that
URL. (CVE-2007-5899)

It was discovered that the PHP fnmatch() function did not restrict the
length of the string argument. An attacker could use this flaw to
crash the PHP interpreter where a script used fnmatch() on untrusted
input data. (CVE-2007-4782)

It was discovered that PHP did not properly seed its pseudo-random
number generator used by functions such as rand() and mt_rand(),
possibly allowing an attacker to easily predict the generated
pseudo-random values. (CVE-2008-2107, CVE-2008-2108)

As well, these updated packages fix the following bug :

* after 2008-01-01, when using PEAR version 1.3.6 or older, it was not
possible to use the PHP Extension and Application Repository (PEAR) to
upgrade or install packages. In these updated packages, PEAR has been
upgraded to version 1.4.9, which restores support for the current
pear.php.net update server. The following changes were made to the
PEAR packages included in php-pear: Console_Getopt and Archive_Tar are
now included by default, and XML_RPC has been upgraded to version
1.5.0.

All php users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b495a100"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49f9ad48"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?259e7943"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.22.12")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-domxml / php-gd / php-imap / php-ldap / etc");
}
