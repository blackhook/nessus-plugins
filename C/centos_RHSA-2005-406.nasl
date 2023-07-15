#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:406 and 
# CentOS Errata and Security Advisory 2005:406 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(23981);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-1392", "CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");
  script_xref(name:"RHSA", value:"2005:406");

  script_name(english:"CentOS 4 : PHP (CESA-2005:406)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix various security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A bug was found in the way PHP processes IFF and JPEG images. It is
possible to cause PHP to consume CPU resources for a short period of
time by supplying a carefully crafted IFF or JPEG image. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2005-0524 and CVE-2005-0525 to these issues.

A buffer overflow bug was also found in the way PHP processes EXIF
image headers. It is possible for an attacker to construct an image
file in such a way it could execute arbitrary instructions when
processed by PHP. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1042 to this issue.

A denial of service bug was found in the way PHP processes EXIF image
headers. It is possible for an attacker to cause PHP to enter an
infinite loop for a short period of time by supplying a carefully
crafted image file to PHP for processing. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-1043 to this issue.

Several bug fixes are also included in this update :

  - some performance issues in the unserialize() function
    have been fixed

  - the behaviour of the interpreter when handling integer
    overflow during conversion of a floating variable to an
    integer has been reverted to match the behaviour used
    upstream; the integer will now be wrapped rather than
    truncated

  - a fix for the virtual() function in the Apache httpd
    module which would flush the response prematurely

  - the hard-coded default 'safe mode' setting is now
    'disabled' rather than 'enabled'; to match the default
    /etc/php.ini setting

  - in the curl extension, safe mode was not enforced for
    'file:///' URL lookups (CVE-2004-1392).

Users of PHP should upgrade to these updated packages, which contain
backported fixes for these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eaed46b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52485d4c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/08");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.6")) flag++;


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
