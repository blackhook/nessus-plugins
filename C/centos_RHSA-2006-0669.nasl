#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0669 and 
# CentOS Errata and Security Advisory 2006:0669 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22423);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-3016", "CVE-2006-4020", "CVE-2006-4482", "CVE-2006-4484", "CVE-2006-4486");
  script_xref(name:"RHSA", value:"2006:0669");

  script_name(english:"CentOS 3 / 4 : php (CESA-2006:0669)");
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

A response-splitting issue was discovered in the PHP session handling.
If a remote attacker can force a carefully crafted session identifier
to be used, a cross-site-scripting or response-splitting attack could
be possible. (CVE-2006-3016)

A buffer overflow was discovered in the PHP sscanf() function. If a
script used the sscanf() function with positional arguments in the
format string, a remote attacker sending a carefully crafted request
could execute arbitrary code as the 'apache' user. (CVE-2006-4020)

An integer overflow was discovered in the PHP wordwrap() and
str_repeat() functions. If a script running on a 64-bit server used
either of these functions on untrusted user data, a remote attacker
sending a carefully crafted request might be able to cause a heap
overflow. (CVE-2006-4482)

A buffer overflow was discovered in the PHP gd extension. If a script
was set up to process GIF images from untrusted sources using the gd
extension, a remote attacker could cause a heap overflow.
(CVE-2006-4484)

An integer overflow was discovered in the PHP memory allocation
handling. On 64-bit platforms, the 'memory_limit' setting was not
enforced correctly, which could allow a denial of service attack by a
remote user. (CVE-2006-4486)

Users of PHP should upgrade to these updated packages which contain
backported patches to correct these issues. These packages also
contain a fix for a bug where certain input strings to the metaphone()
function could cause memory corruption."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16073a4e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4af8cff"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013279.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?175e5c9b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e97c6b1e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c131124"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98c2bc17"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-36.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-36.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-36.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-36.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-36.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-36.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-36.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.18")) flag++;


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
