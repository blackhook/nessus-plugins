#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:3736. The text
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130739);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"RHSA", value:"2019:3736");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"RHEL 8 : php:7.3 (RHSA-2019:3736)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for the php:7.3 module is now available for Red Hat
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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3736");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-11043");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libzip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-apcu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-zip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.3');
if ('7.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

appstreams = {
    'php:7.3': [
      {'reference':'apcu-panel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'release':'8'},
      {'reference':'libzip-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'libzip-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'libzip-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'libzip-debugsource-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'libzip-debugsource-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'libzip-debugsource-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'libzip-devel-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'libzip-devel-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'libzip-devel-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'libzip-tools-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'libzip-tools-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'libzip-tools-1.5.2-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-bcmath-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-bcmath-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-bcmath-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-cli-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-cli-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-cli-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-common-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-common-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-common-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-dba-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-dba-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-dba-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-dbg-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-dbg-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-dbg-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-debugsource-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-debugsource-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-debugsource-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-devel-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-devel-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-devel-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-embedded-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-embedded-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-embedded-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-enchant-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-enchant-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-enchant-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-fpm-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-fpm-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-fpm-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-gd-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-gd-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-gd-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-gmp-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-gmp-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-gmp-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-intl-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-intl-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-intl-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-json-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-json-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-json-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-ldap-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-ldap-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-ldap-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-mbstring-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-mbstring-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-mbstring-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-mysqlnd-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-mysqlnd-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-mysqlnd-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-odbc-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-odbc-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-odbc-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-opcache-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-opcache-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-opcache-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-pdo-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-pdo-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-pdo-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-pear-1.10.9-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'epoch':'1'},
      {'reference':'php-pecl-apcu-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-pecl-apcu-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-pecl-apcu-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-pecl-apcu-debugsource-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-pecl-apcu-debugsource-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-pecl-apcu-debugsource-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-pecl-zip-1.15.4-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-pecl-zip-1.15.4-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-pecl-zip-1.15.4-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-pecl-zip-debugsource-1.15.4-1.module+el8.1.0+3189+a1bff096', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-pecl-zip-debugsource-1.15.4-1.module+el8.1.0+3189+a1bff096', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-pecl-zip-debugsource-1.15.4-1.module+el8.1.0+3189+a1bff096', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-pgsql-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-pgsql-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-pgsql-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-process-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-process-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-process-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-recode-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-recode-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-recode-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-snmp-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-snmp-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-snmp-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-soap-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-soap-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-soap-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-xml-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-xml-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-xml-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'},
      {'reference':'php-xmlrpc-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'aarch64', 'release':'8'},
      {'reference':'php-xmlrpc-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'s390x', 'release':'8'},
      {'reference':'php-xmlrpc-7.3.5-5.module+el8.1.0+4560+e0eee7d6', 'cpu':'x86_64', 'release':'8'}
    ],
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-debugsource / etc');
}
