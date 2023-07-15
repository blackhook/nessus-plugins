#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0276 and 
# CentOS Errata and Security Advisory 2006:0276 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21897);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2003-1303", "CVE-2005-2933", "CVE-2005-3883", "CVE-2006-0208", "CVE-2006-0996", "CVE-2006-1490");
  script_bugtraq_id(15009);
  script_xref(name:"RHSA", value:"2006:0276");

  script_name(english:"CentOS 3 / 4 : php (CESA-2006:0276)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

The phpinfo() PHP function did not properly sanitize long strings. An
attacker could use this to perform cross-site scripting attacks
against sites that have publicly-available PHP scripts that call
phpinfo(). (CVE-2006-0996)

The html_entity_decode() PHP function was found to not be binary safe.
An attacker could use this flaw to disclose a certain part of the
memory. In order for this issue to be exploitable the target site
would need to have a PHP script which called the
'html_entity_decode()' function with untrusted input from the user and
displayed the result. (CVE-2006-1490)

The error handling output was found to not properly escape HTML output
in certain cases. An attacker could use this flaw to perform
cross-site scripting attacks against sites where both display_errors
and html_errors are enabled. (CVE-2006-0208)

An input validation error was found in the 'mb_send_mail()' function.
An attacker could use this flaw to inject arbitrary headers in a mail
sent via a script calling the 'mb_send_mail()' function where the 'To'
parameter can be controlled by the attacker. (CVE-2005-3883)

A buffer overflow flaw was discovered in uw-imap, the University of
Washington's IMAP Server. php-imap is compiled against the static
c-client libraries from imap and therefore needed to be recompiled
against the fixed version. This issue only affected Red Hat Enterprise
Linux 3. (CVE-2005-2933).

Users of PHP should upgrade to these updated packages, which contain
backported patches that resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcbaf17b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9183d70"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012849.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d61c26ac"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?105562df"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012853.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e77e3a03"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-30.ent")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-devel-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-devel-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-domxml-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-domxml-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-gd-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-gd-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-imap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-imap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-ldap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-ldap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-mbstring-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-mbstring-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-mysql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-mysql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-ncurses-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-ncurses-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-odbc-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-odbc-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-pear-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-pear-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-pgsql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-pgsql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-snmp-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-snmp-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-xmlrpc-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-xmlrpc-4.3.9-3.12")) flag++;


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
