##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0059. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143917);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id(
    "CVE-2018-5712",
    "CVE-2018-7584",
    "CVE-2018-10547",
    "CVE-2019-9024"
  );
  script_bugtraq_id(
    102742,
    103204,
    104020,
    107156
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : php Multiple Vulnerabilities (NS-SA-2020-0059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has php packages installed that are affected by
multiple vulnerabilities:

  - In PHP through 5.6.33, 7.0.x before 7.0.28, 7.1.x through 7.1.14, and 7.2.x through 7.2.2, there is a
    stack-based buffer under-read while parsing an HTTP response in the php_stream_url_wrap_http_ex function
    in ext/standard/http_fopen_wrapper.c. This subsequently results in copying a large string. (CVE-2018-7584)

  - An issue was discovered in ext/phar/phar_object.c in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before
    7.1.17, and 7.2.x before 7.2.5. There is Reflected XSS on the PHAR 403 and 404 error pages via request
    data of a request for a .phar file. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2018-5712. (CVE-2018-10547)

  - An issue was discovered in PHP before 5.6.33, 7.0.x before 7.0.27, 7.1.x before 7.1.13, and 7.2.x before
    7.2.1. There is Reflected XSS on the PHAR 404 error page via the URI of a request for a .phar file.
    (CVE-2018-5712)

  - An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. xmlrpc_decode() can allow a hostile XMLRPC server to cause PHP to read memory outside of allocated
    areas in base64_decode_xmlrpc in ext/xmlrpc/libxmlrpc/base64.c. (CVE-2019-9024)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0059");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL php packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7584");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'php-5.4.16-48.el7',
    'php-bcmath-5.4.16-48.el7',
    'php-cli-5.4.16-48.el7',
    'php-common-5.4.16-48.el7',
    'php-dba-5.4.16-48.el7',
    'php-debuginfo-5.4.16-48.el7',
    'php-devel-5.4.16-48.el7',
    'php-embedded-5.4.16-48.el7',
    'php-enchant-5.4.16-48.el7',
    'php-fpm-5.4.16-48.el7',
    'php-gd-5.4.16-48.el7',
    'php-intl-5.4.16-48.el7',
    'php-ldap-5.4.16-48.el7',
    'php-mbstring-5.4.16-48.el7',
    'php-mysql-5.4.16-48.el7',
    'php-mysqlnd-5.4.16-48.el7',
    'php-odbc-5.4.16-48.el7',
    'php-pdo-5.4.16-48.el7',
    'php-pgsql-5.4.16-48.el7',
    'php-process-5.4.16-48.el7',
    'php-pspell-5.4.16-48.el7',
    'php-recode-5.4.16-48.el7',
    'php-snmp-5.4.16-48.el7',
    'php-soap-5.4.16-48.el7',
    'php-xml-5.4.16-48.el7',
    'php-xmlrpc-5.4.16-48.el7'
  ],
  'CGSL MAIN 5.04': [
    'php-5.4.16-48.el7',
    'php-bcmath-5.4.16-48.el7',
    'php-cli-5.4.16-48.el7',
    'php-common-5.4.16-48.el7',
    'php-dba-5.4.16-48.el7',
    'php-debuginfo-5.4.16-48.el7',
    'php-devel-5.4.16-48.el7',
    'php-embedded-5.4.16-48.el7',
    'php-enchant-5.4.16-48.el7',
    'php-fpm-5.4.16-48.el7',
    'php-gd-5.4.16-48.el7',
    'php-intl-5.4.16-48.el7',
    'php-ldap-5.4.16-48.el7',
    'php-mbstring-5.4.16-48.el7',
    'php-mysql-5.4.16-48.el7',
    'php-mysqlnd-5.4.16-48.el7',
    'php-odbc-5.4.16-48.el7',
    'php-pdo-5.4.16-48.el7',
    'php-pgsql-5.4.16-48.el7',
    'php-process-5.4.16-48.el7',
    'php-pspell-5.4.16-48.el7',
    'php-recode-5.4.16-48.el7',
    'php-snmp-5.4.16-48.el7',
    'php-soap-5.4.16-48.el7',
    'php-xml-5.4.16-48.el7',
    'php-xmlrpc-5.4.16-48.el7'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php');
}
