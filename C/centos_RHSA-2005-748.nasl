#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:748 and 
# CentOS Errata and Security Advisory 2005:748 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21960);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2498");
  script_xref(name:"RHSA", value:"2005:748");

  script_name(english:"CentOS 3 / 4 : php (CESA-2005:748)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A bug was discovered in the PEAR XML-RPC Server package included in
PHP. If a PHP script is used which implements an XML-RPC Server using
the PEAR XML-RPC package, then it is possible for a remote attacker to
construct an XML-RPC request which can cause PHP to execute arbitrary
PHP commands as the 'apache' user. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-2498
to this issue.

When using the default SELinux 'targeted' policy on Red Hat Enterprise
Linux 4, the impact of this issue is reduced since the scripts
executed by PHP are constrained within the httpd_sys_script_t security
context.

Users of PHP should upgrade to these updated packages, which contain
backported fixes for these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b97ebaa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dfaa41c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012073.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?624f7398"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012074.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49013789"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d34e124a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f917bd9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"php-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"php-4.3.2-25.ent")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"php-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"php-devel-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"php-devel-4.3.2-25.ent")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"php-devel-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"php-imap-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"php-imap-4.3.2-25.ent")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"php-imap-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"php-ldap-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"php-ldap-4.3.2-25.ent")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"php-ldap-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"php-mysql-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"php-mysql-4.3.2-25.ent")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"php-mysql-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"php-odbc-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"php-odbc-4.3.2-25.ent")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"php-odbc-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"php-pgsql-4.3.2-25.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"php-pgsql-4.3.2-25.ent")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"php-pgsql-4.3.2-25.ent.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.8")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
