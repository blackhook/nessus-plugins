#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0406 and 
# CentOS Errata and Security Advisory 2018:0406 respectively.
#

include("compat.inc");

if (description)
{
  script_id(107272);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-7890");
  script_xref(name:"RHSA", value:"2018:0406");

  script_name(english:"CentOS 7 : php (CESA-2018:0406)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for php is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

Security Fix(es) :

* php: Buffer over-read from uninitialized data in
gdImageCreateFromGifCtx function (CVE-2017-7890)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-March/022772.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41a4d178"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7890");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-bcmath-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-cli-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-common-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-dba-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-devel-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-embedded-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-enchant-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-fpm-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-gd-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-intl-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-ldap-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mbstring-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysql-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-odbc-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pdo-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pgsql-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-process-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pspell-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-recode-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-snmp-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-soap-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xml-5.4.16-43.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-43.el7_4.1")) flag++;


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
