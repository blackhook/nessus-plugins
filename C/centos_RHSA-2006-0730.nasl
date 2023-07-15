#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0730 and 
# CentOS Errata and Security Advisory 2006:0730 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37281);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-5465");
  script_bugtraq_id(20879);
  script_xref(name:"RHSA", value:"2006:0730");

  script_name(english:"CentOS 3 / 4 : php (CESA-2006:0730)");
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

The Hardened-PHP Project discovered an overflow in the PHP
htmlentities() and htmlspecialchars() routines. If a PHP script used
the vulnerable functions to parse UTF-8 data, a remote attacker
sending a carefully crafted request could trigger the overflow and
potentially execute arbitrary code as the 'apache' user.
(CVE-2006-5465)

Users of PHP should upgrade to these updated packages which contain a
backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?992951c1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e16d410"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fea975bb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013354.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42467017"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f38cb90"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cf3ca71"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-37.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.22")) flag++;


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
