#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1813 and 
# CentOS Errata and Security Advisory 2013:1813 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71355);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-6420");
  script_bugtraq_id(64225);
  script_xref(name:"RHSA", value:"2013:1813");

  script_name(english:"CentOS 5 / 6 : php / php53 (CESA-2013:1813)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php53 and php packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6 respectively.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A memory corruption flaw was found in the way the openssl_x509_parse()
function of the PHP openssl extension parsed X.509 certificates. A
remote attacker could use this flaw to provide a malicious self-signed
certificate or a certificate signed by a trusted authority to a PHP
application using the aforementioned function, causing the application
to crash or, possibly, allow the attacker to execute arbitrary code
with the privileges of the user running the PHP interpreter.
(CVE-2013-6420)

Red Hat would like to thank the PHP project for reporting this issue.
Upstream acknowledges Stefan Esser as the original reporter of this
issue.

All php53 and php users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-December/020061.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41c1e113"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-December/020063.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d06516f4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php and / or php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6420");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-zts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"php53-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-bcmath-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-cli-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-common-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-dba-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-devel-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-gd-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-imap-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-intl-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-ldap-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mbstring-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mysql-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-odbc-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pdo-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pgsql-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-process-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pspell-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-snmp-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-soap-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xml-5.3.3-22.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xmlrpc-5.3.3-22.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-27.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-27.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc");
}
