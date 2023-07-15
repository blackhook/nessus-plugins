##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0066. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143931);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id("CVE-2017-15710", "CVE-2018-1301", "CVE-2018-17199");
  script_bugtraq_id(103512, 103515, 106742);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : httpd Multiple Vulnerabilities (NS-SA-2020-0066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has httpd packages installed that are affected by
multiple vulnerabilities:

  - A specially crafted request could have crashed the Apache HTTP Server prior to version 2.4.30, due to an
    out of bound access after a size limit is reached by reading the HTTP header. This vulnerability is
    considered very hard if not impossible to trigger in non-debug mode (both log and build level), so it is
    classified as low risk for common server usage. (CVE-2018-1301)

  - In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29, mod_authnz_ldap, if configured
    with AuthLDAPCharsetConfig, uses the Accept-Language header value to lookup the right charset encoding
    when verifying the user's credentials. If the header value is not present in the charset conversion table,
    a fallback mechanism is used to truncate it to a two characters value to allow a quick retry (for example,
    'en-US' is truncated to 'en'). A header value of less than two characters forces an out of bound write of
    one NUL byte to a memory location that is not part of the string. In the worst case, quite unlikely, the
    process would crash which could be used as a Denial of Service attack. In the more likely case, this
    memory is already reserved for future use and the issue has no effect at all. (CVE-2017-15710)

  - In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session expiry time before
    decoding the session. This causes session expiry time to be ignored for mod_session_cookie sessions since
    the expiry time is loaded when the session is decoded. (CVE-2018-17199)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0066");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17199");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/21");
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
    'httpd-2.4.6-93.el7.centos',
    'httpd-debuginfo-2.4.6-93.el7.centos',
    'httpd-devel-2.4.6-93.el7.centos',
    'httpd-manual-2.4.6-93.el7.centos',
    'httpd-tools-2.4.6-93.el7.centos',
    'mod_ldap-2.4.6-93.el7.centos',
    'mod_proxy_html-2.4.6-93.el7.centos',
    'mod_session-2.4.6-93.el7.centos',
    'mod_ssl-2.4.6-93.el7.centos'
  ],
  'CGSL MAIN 5.04': [
    'httpd-2.4.6-93.el7.centos',
    'httpd-debuginfo-2.4.6-93.el7.centos',
    'httpd-devel-2.4.6-93.el7.centos',
    'httpd-manual-2.4.6-93.el7.centos',
    'httpd-tools-2.4.6-93.el7.centos',
    'mod_ldap-2.4.6-93.el7.centos',
    'mod_proxy_html-2.4.6-93.el7.centos',
    'mod_session-2.4.6-93.el7.centos',
    'mod_ssl-2.4.6-93.el7.centos'
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
