#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0311 and 
# CentOS Errata and Security Advisory 2014:0311 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73085);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-7243", "CVE-2009-0689");
  script_bugtraq_id(44951);
  script_xref(name:"RHSA", value:"2014:0311");

  script_name(english:"CentOS 5 : php (CESA-2014:0311)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A buffer overflow flaw was found in the way PHP parsed floating point
numbers from their text representation. If a PHP application converted
untrusted input strings to numbers, an attacker able to provide such
input could cause the application to crash or, possibly, execute
arbitrary code with the privileges of the application. (CVE-2009-0689)

It was found that PHP did not properly handle file names with a NULL
character. A remote attacker could possibly use this flaw to make a
PHP script access unexpected files and bypass intended file system
access restrictions. (CVE-2006-7243)

All php users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-March/020214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55a73544"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0689");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"php-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-bcmath-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-cli-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-common-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-dba-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-devel-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-gd-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-imap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ldap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mbstring-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mysql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ncurses-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-odbc-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pdo-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pgsql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-snmp-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-soap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xml-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xmlrpc-5.1.6-44.el5_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc");
}
