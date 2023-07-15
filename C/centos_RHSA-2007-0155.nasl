#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0155 and 
# CentOS Errata and Security Advisory 2007:0155 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25043);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0455", "CVE-2007-1001", "CVE-2007-1285", "CVE-2007-1286", "CVE-2007-1583", "CVE-2007-1711", "CVE-2007-1718");
  script_bugtraq_id(22764, 22765, 23016, 23145, 23357);
  script_xref(name:"RHSA", value:"2007:0155");

  script_name(english:"CentOS 3 / 4 : php (CESA-2007:0155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A denial of service flaw was found in the way PHP processed a deeply
nested array. A remote attacker could cause the PHP interpreter to
crash by submitting an input variable with a deeply nested array.
(CVE-2007-1285)

A flaw was found in the way PHP's unserialize() function processed
data. If a remote attacker was able to pass arbitrary data to PHP's
unserialize() function, they could possibly execute arbitrary code as
the apache user. (CVE-2007-1286)

A flaw was found in the way the mbstring extension set global
variables. A script which used the mb_parse_str() function to set
global variables could be forced to enable the register_globals
configuration option, possibly resulting in global variable injection.
(CVE-2007-1583)

A double free flaw was found in PHP's session_decode() function. If a
remote attacker was able to pass arbitrary data to PHP's
session_decode() function, they could possibly execute arbitrary code
as the apache user. (CVE-2007-1711)

A flaw was discovered in the way PHP's mail() function processed
header data. If a script sent mail using a Subject header containing a
string from an untrusted source, a remote attacker could send bulk
e-mail to unintended recipients. (CVE-2007-1718)

A heap based buffer overflow flaw was discovered in PHP's gd
extension. A script that could be forced to process WBMP images from
an untrusted source could result in arbitrary code execution.
(CVE-2007-1001)

A buffer over-read flaw was discovered in PHP's gd extension. A script
that could be forced to write arbitrary string using a JIS font from
an untrusted source could cause the PHP interpreter to crash.
(CVE-2007-0455)

Users of PHP should upgrade to these updated packages which contain
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aa1da2d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013672.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00b4b6bf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013677.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b57e934e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013678.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84a6c30c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05af58a3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013683.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2d68f08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-40.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-40.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-40.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-40.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-40.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-40.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-40.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.22.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.22.4")) flag++;


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
