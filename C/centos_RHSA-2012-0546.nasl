#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0546 and 
# CentOS Errata and Security Advisory 2012:0546 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59021);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/28");

  script_cve_id("CVE-2012-1823");
  script_bugtraq_id(53388);
  script_xref(name:"RHSA", value:"2012:0546");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"CentOS 5 / 6 : php (CESA-2012:0546)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated php packages that fix one security issue are now available for
Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A flaw was found in the way the php-cgi executable processed command
line arguments when running in CGI mode. A remote attacker could send
a specially crafted request to a PHP script that would result in the
query string being parsed by php-cgi as command line options and
arguments. This could lead to the disclosure of the script's source
code or arbitrary code execution with the privileges of the PHP
interpreter. (CVE-2012-1823)

Red Hat is aware that a public exploit for this issue is available
that allows remote code execution in affected PHP CGI configurations.
This flaw does not affect the default configuration in Red Hat
Enterprise Linux 5 and 6 using the PHP module for Apache httpd to
handle PHP scripts.

All php users should upgrade to these updated packages, which contain
a backported patch to resolve this issue. After installing the updated
packages, the httpd daemon must be restarted for the update to take
effect.");
  # https://lists.centos.org/pipermail/centos-announce/2012-May/018613.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0fae3d8");
  # https://lists.centos.org/pipermail/centos-announce/2012-May/018614.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e175f160");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1823");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-5", reference:"php-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-bcmath-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-cli-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-common-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-dba-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-devel-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-gd-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-imap-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ldap-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mbstring-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mysql-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ncurses-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-odbc-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pdo-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pgsql-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-snmp-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-soap-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xml-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xmlrpc-5.1.6-34.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-3.el6_2.8")) flag++;


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
