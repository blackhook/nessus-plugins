##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0036. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147353);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-15715",
    "CVE-2018-1283",
    "CVE-2018-1303",
    "CVE-2019-10098",
    "CVE-2020-1927",
    "CVE-2020-1934"
  );
  script_bugtraq_id(103520, 103522, 103525);
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : httpd Multiple Vulnerabilities (NS-SA-2021-0036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has httpd packages installed that are affected by
multiple vulnerabilities:

  - In Apache HTTP server 2.4.0 to 2.4.39, Redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an unexpected URL within the
    request URL. (CVE-2019-10098)

  - In Apache httpd 2.4.0 to 2.4.29, when mod_session is configured to forward its session data to CGI
    applications (SessionEnv on, not the default), a remote user may influence their content by using a
    Session header. This comes from the HTTP_SESSION variable name used by mod_session to forward its data
    to CGIs, since the prefix HTTP_ is also used by the Apache HTTP Server to pass HTTP header fields, per
    CGI specifications. (CVE-2018-1283)

  - A specially crafted HTTP request header could have crashed the Apache HTTP Server prior to version 2.4.30
    due to an out of bound read while preparing data to be cached in shared memory. It could be used as a
    Denial of Service attack against users of mod_cache_socache. The vulnerability is considered as low risk
    since mod_cache_socache is not widely used, mod_cache_disk is not concerned by this vulnerability.
    (CVE-2018-1303)

  - In Apache httpd 2.4.0 to 2.4.29, the expression specified in  could match '$' to a newline
    character in a malicious filename, rather than matching only the end of the filename. This could be
    exploited in environments where uploads of some files are are externally blocked, but only by matching the
    trailing portion of the filename. (CVE-2017-15715)

  - In Apache HTTP Server 2.4.0 to 2.4.41, redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an an unexpected URL within
    the request URL. (CVE-2020-1927)

  - In Apache HTTP Server 2.4.0 to 2.4.41, mod_proxy_ftp may use uninitialized memory when proxying to a
    malicious FTP server. (CVE-2020-1934)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0036");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15715");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/21");
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
    'httpd-2.4.6-97.el7.centos',
    'httpd-devel-2.4.6-97.el7.centos',
    'httpd-manual-2.4.6-97.el7.centos',
    'httpd-tools-2.4.6-97.el7.centos',
    'mod_ldap-2.4.6-97.el7.centos',
    'mod_proxy_html-2.4.6-97.el7.centos',
    'mod_session-2.4.6-97.el7.centos',
    'mod_ssl-2.4.6-97.el7.centos'
  ],
  'CGSL MAIN 5.04': [
    'httpd-2.4.6-97.el7.centos',
    'httpd-devel-2.4.6-97.el7.centos',
    'httpd-manual-2.4.6-97.el7.centos',
    'httpd-tools-2.4.6-97.el7.centos',
    'mod_ldap-2.4.6-97.el7.centos',
    'mod_proxy_html-2.4.6-97.el7.centos',
    'mod_session-2.4.6-97.el7.centos',
    'mod_ssl-2.4.6-97.el7.centos'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd');
}
