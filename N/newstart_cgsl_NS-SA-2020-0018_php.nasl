#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0018. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134323);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"NewStart CGSL MAIN 4.05 : php Vulnerability (NS-SA-2020-0018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has php packages installed that are affected by a
vulnerability:

  - In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24
    and 7.3.x below 7.3.11 in certain configurations of FPM
    setup it is possible to cause FPM module to write past
    allocated buffers into the space reserved for FCGI
    protocol data, thus opening the possibility of remote
    code execution. (CVE-2019-11043)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0018");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL php packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "php-5.3.3-50.el6_10",
    "php-bcmath-5.3.3-50.el6_10",
    "php-cli-5.3.3-50.el6_10",
    "php-common-5.3.3-50.el6_10",
    "php-dba-5.3.3-50.el6_10",
    "php-debuginfo-5.3.3-50.el6_10",
    "php-devel-5.3.3-50.el6_10",
    "php-embedded-5.3.3-50.el6_10",
    "php-enchant-5.3.3-50.el6_10",
    "php-fpm-5.3.3-50.el6_10",
    "php-gd-5.3.3-50.el6_10",
    "php-imap-5.3.3-50.el6_10",
    "php-intl-5.3.3-50.el6_10",
    "php-ldap-5.3.3-50.el6_10",
    "php-mbstring-5.3.3-50.el6_10",
    "php-mysql-5.3.3-50.el6_10",
    "php-odbc-5.3.3-50.el6_10",
    "php-pdo-5.3.3-50.el6_10",
    "php-pgsql-5.3.3-50.el6_10",
    "php-process-5.3.3-50.el6_10",
    "php-pspell-5.3.3-50.el6_10",
    "php-recode-5.3.3-50.el6_10",
    "php-snmp-5.3.3-50.el6_10",
    "php-soap-5.3.3-50.el6_10",
    "php-tidy-5.3.3-50.el6_10",
    "php-xml-5.3.3-50.el6_10",
    "php-xmlrpc-5.3.3-50.el6_10",
    "php-zts-5.3.3-50.el6_10"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
