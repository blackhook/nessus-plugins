#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3221 and 
# CentOS Errata and Security Advisory 2017:3221 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104584);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-10167", "CVE-2016-10168");
  script_xref(name:"RHSA", value:"2017:3221");

  script_name(english:"CentOS 7 : php (CESA-2017:3221)");
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

* A NULL pointer dereference flaw was found in libgd. An attacker
could use a specially crafted .gd2 file to cause an application linked
with libgd to crash, leading to denial of service. (CVE-2016-10167)

* An integer overflow flaw, leading to a heap-based buffer overflow
was found in the way libgd read some specially crafted gd2 files. A
remote attacker could use this flaw to crash an application compiled
with libgd or in certain cases execute arbitrary code with the
privileges of the user running that application. (CVE-2016-10168)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-November/022613.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8eed4c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10168");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-bcmath-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-cli-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-common-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-dba-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-devel-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-embedded-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-enchant-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-fpm-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-gd-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-intl-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-ldap-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mbstring-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysql-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-odbc-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pdo-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pgsql-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-process-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pspell-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-recode-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-snmp-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-soap-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xml-5.4.16-43.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-43.el7_4")) flag++;


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
