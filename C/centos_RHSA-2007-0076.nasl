#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0076 and 
# CentOS Errata and Security Advisory 2007:0076 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24673);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988", "CVE-2007-1380", "CVE-2007-1701", "CVE-2007-1825");
  script_bugtraq_id(22496);
  script_xref(name:"RHSA", value:"2007:0076");

  script_name(english:"CentOS 3 / 4 : php (CESA-2007:0076)");
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

A number of buffer overflow flaws were found in the PHP session
extension, the str_replace() function, and the imap_mail_compose()
function. If very long strings under the control of an attacker are
passed to the str_replace() function then an integer overflow could
occur in memory allocation. If a script uses the imap_mail_compose()
function to create a new MIME message based on an input body from an
untrusted source, it could result in a heap overflow. An attacker who
is able to access a PHP application affected by any these issues could
trigger these flaws and possibly execute arbitrary code as the
'apache' user. (CVE-2007-0906)

If unserializing untrusted data on 64-bit platforms, the
zend_hash_init() function can be forced to enter an infinite loop,
consuming CPU resources for a limited length of time, until the script
timeout alarm aborts execution of the script. (CVE-2007-0988)

If the wddx extension is used to import WDDX data from an untrusted
source, certain WDDX input packets may allow a random portion of heap
memory to be exposed. (CVE-2007-0908)

If the odbc_result_all() function is used to display data from a
database, and the contents of the database table are under the control
of an attacker, a format string vulnerability is possible which could
lead to the execution of arbitrary code. (CVE-2007-0909)

A one byte memory read will always occur before the beginning of a
buffer, which could be triggered for example by any use of the
header() function in a script. However it is unlikely that this would
have any effect. (CVE-2007-0907)

Several flaws in PHP could allows attackers to 'clobber' certain
super-global variables via unspecified vectors. (CVE-2007-0910)

Users of PHP should upgrade to these updated packages which contain
backported patches to correct these issues.

Red Hat would like to thank Stefan Esser for his help diagnosing these
issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013543.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3940e92c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8b50cef"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5afc62e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43c21194"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013558.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?187f0d51"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8af9a87"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 399);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/21");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-39.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-39.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-39.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-39.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-39.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-39.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-39.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.22.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.22.3")) flag++;


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
