#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:831 and 
# CentOS Errata and Security Advisory 2005:831 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21871);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3353", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390");
  script_bugtraq_id(15248, 15249, 15250);
  script_xref(name:"RHSA", value:"2005:831");

  script_name(english:"CentOS 3 / 4 : php (CESA-2005:831)");
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

A flaw was found in the way PHP registers global variables during a
file upload request. A remote attacker could submit a carefully
crafted multipart/form-data POST request that would overwrite the
$GLOBALS array, altering expected script behavior, and possibly
leading to the execution of arbitrary PHP commands. Please note that
this vulnerability only affects installations which have
register_globals enabled in the PHP configuration file, which is not a
default or recommended option. The Common Vulnerabilities and
Exposures project assigned the name CVE-2005-3390 to this issue.

A flaw was found in the PHP parse_str() function. If a PHP script
passes only one argument to the parse_str() function, and the script
can be forced to abort execution during operation (for example due to
the memory_limit setting), the register_globals may be enabled even if
it is disabled in the PHP configuration file. This vulnerability only
affects installations that have PHP scripts using the parse_str
function in this way. (CVE-2005-3389)

A Cross-Site Scripting flaw was found in the phpinfo() function. If a
victim can be tricked into following a malicious URL to a site with a
page displaying the phpinfo() output, it may be possible to inject
JavaScript or HTML content into the displayed page or steal data such
as cookies. This vulnerability only affects installations which allow
users to view the output of the phpinfo() function. As the phpinfo()
function outputs a large amount of information about the current state
of PHP, it should only be used during debugging or if protected by
authentication. (CVE-2005-3388)

A denial of service flaw was found in the way PHP processes EXIF image
data. It is possible for an attacker to cause PHP to crash by
supplying carefully crafted EXIF image data. (CVE-2005-3353)

Users of PHP should upgrade to these updated packages, which contain
backported patches that resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012393.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ba48b5d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012394.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7b67205"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?359a2fea"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012400.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61d76502"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e53e54cf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48e764fc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/10");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-26.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-26.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-26.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-26.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-26.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-26.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-26.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.9")) flag++;


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
