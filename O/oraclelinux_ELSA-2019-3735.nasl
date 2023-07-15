#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:3735 and 
# Oracle Linux Security Advisory ELSA-2019-3735 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131270);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"RHSA", value:"2019:3735");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"Oracle Linux 8 : php:7.2 (ELSA-2019-3735)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2019:3735 :

An update for the php:7.2 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

Security Fix(es) :

* php: underflow in env_path_info in fpm_main.c (CVE-2019-11043)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2019-November/009383.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected php:7.2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"apcu-panel-5.1.12-2.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libzip-1.5.1-2.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libzip-devel-1.5.1-2.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libzip-tools-1.5.1-2.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-bcmath-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-cli-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-common-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-dba-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-dbg-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-devel-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-embedded-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-enchant-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-fpm-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-gd-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-gmp-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-intl-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-json-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-ldap-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-mbstring-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-mysqlnd-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-odbc-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-opcache-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-pdo-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-pear-1.10.5-9.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-pecl-apcu-5.1.12-2.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-pecl-apcu-devel-5.1.12-2.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-pecl-zip-1.15.3-1.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-pgsql-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-process-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-recode-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-snmp-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-soap-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-xml-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"php-xmlrpc-7.2.11-4.module+el8.1.0+5443+bc1aeb77")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apcu-panel / libzip / libzip-devel / libzip-tools / php / etc");
}
