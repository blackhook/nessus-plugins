#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1609 and 
# CentOS Errata and Security Advisory 2016:1609 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92872);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-5385");
  script_xref(name:"RHSA", value:"2016:1609");

  script_name(english:"CentOS 6 : php (CESA-2016:1609) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for php is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

Security Fix(es) :

* It was discovered that PHP did not properly protect against the
HTTP_PROXY variable name clash. A remote attacker could possibly use
this flaw to redirect HTTP requests performed by a PHP script to an
attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5385)

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-August/022034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bedfe3eb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5385");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-48.el6_8")) flag++;


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
