##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0028. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147349);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-17563", "CVE-2020-1935", "CVE-2020-13935");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : tomcat Multiple Vulnerabilities (NS-SA-2021-0028)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has tomcat packages installed that are affected by
multiple vulnerabilities:

  - When using FORM authentication with Apache Tomcat 9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49 and 7.0.0 to 7.0.98
    there was a narrow window where an attacker could perform a session fixation attack. The window was
    considered too narrow for an exploit to be practical but, erring on the side of caution, this issue has
    been treated as a security vulnerability. (CVE-2019-17563)

  - In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99 the HTTP header parsing code used
    an approach to end-of-line parsing that allowed some invalid HTTP headers to be parsed as valid. This led
    to a possibility of HTTP Request Smuggling if Tomcat was located behind a reverse proxy that incorrectly
    handled the invalid Transfer-Encoding header in a particular manner. Such a reverse proxy is considered
    unlikely. (CVE-2020-1935)

  - The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to
    10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could
    trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of
    service. (CVE-2020-13935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0028");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL tomcat packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1935");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17563");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'tomcat-7.0.76-16.el7_9',
    'tomcat-admin-webapps-7.0.76-16.el7_9',
    'tomcat-docs-webapp-7.0.76-16.el7_9',
    'tomcat-el-2.2-api-7.0.76-16.el7_9',
    'tomcat-javadoc-7.0.76-16.el7_9',
    'tomcat-jsp-2.2-api-7.0.76-16.el7_9',
    'tomcat-jsvc-7.0.76-16.el7_9',
    'tomcat-lib-7.0.76-16.el7_9',
    'tomcat-servlet-3.0-api-7.0.76-16.el7_9',
    'tomcat-webapps-7.0.76-16.el7_9'
  ],
  'CGSL MAIN 5.04': [
    'tomcat-7.0.76-16.el7_9',
    'tomcat-admin-webapps-7.0.76-16.el7_9',
    'tomcat-docs-webapp-7.0.76-16.el7_9',
    'tomcat-el-2.2-api-7.0.76-16.el7_9',
    'tomcat-javadoc-7.0.76-16.el7_9',
    'tomcat-jsp-2.2-api-7.0.76-16.el7_9',
    'tomcat-jsvc-7.0.76-16.el7_9',
    'tomcat-lib-7.0.76-16.el7_9',
    'tomcat-servlet-3.0-api-7.0.76-16.el7_9',
    'tomcat-webapps-7.0.76-16.el7_9'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat');
}
