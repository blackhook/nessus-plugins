##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0060. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143907);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id(
    "CVE-2018-1000024",
    "CVE-2018-1000027",
    "CVE-2019-12519",
    "CVE-2019-12525",
    "CVE-2019-13345",
    "CVE-2020-11945"
  );
  script_bugtraq_id(109095, 109382);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : squid Multiple Vulnerabilities (NS-SA-2020-0060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has squid packages installed that are affected by
multiple vulnerabilities:

  - An issue was discovered in Squid through 4.7. When handling the tag esi:when when ESI is enabled, Squid
    calls ESIExpression::Evaluate. This function uses a fixed stack buffer to hold the expression while it's
    being evaluated. When processing the expression, it could either evaluate the top of the stack, or add a
    new member to the stack. When adding a new member, there is no check to ensure that the stack won't
    overflow. (CVE-2019-12519)

  - An issue was discovered in Squid before 5.0.2. A remote attacker can replay a sniffed Digest
    Authentication nonce to gain access to resources that are otherwise forbidden. This occurs because the
    attacker can overflow the nonce reference counter (a short integer). Remote code execution may occur if
    the pooled token credentials are freed (instead of replayed as valid credentials). (CVE-2020-11945)

  - The Squid Software Foundation Squid HTTP Caching Proxy version 3.0 to 3.5.27, 4.0 to 4.0.22 contains a
    Incorrect Pointer Handling vulnerability in ESI Response Processing that can result in Denial of Service
    for all clients using the proxy.. This attack appear to be exploitable via Remote server delivers an HTTP
    response payload containing valid but unusual ESI syntax.. This vulnerability appears to have been fixed
    in 4.0.23 and later. (CVE-2018-1000024)

  - The Squid Software Foundation Squid HTTP Caching Proxy version prior to version 4.0.23 contains a NULL
    Pointer Dereference vulnerability in HTTP Response X-Forwarded-For header processing that can result in
    Denial of Service to all clients of the proxy. This attack appear to be exploitable via Remote HTTP server
    responding with an X-Forwarded-For header to certain types of HTTP request. This vulnerability appears to
    have been fixed in 4.0.23 and later. (CVE-2018-1000027)

  - An issue was discovered in Squid 3.3.9 through 3.5.28 and 4.x through 4.7. When Squid is configured to use
    Digest authentication, it parses the header Proxy-Authorization. It searches for certain tokens such as
    domain, uri, and qop. Squid checks if this token's value starts with a quote and ends with one. If so, it
    performs a memcpy of its length minus 2. Squid never checks whether the value is just a single quote
    (which would satisfy its requirements), leading to a memcpy of its length minus 1. (CVE-2019-12525)

  - The cachemgr.cgi web module of Squid through 4.7 has XSS via the user_name or auth parameter.
    (CVE-2019-13345)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0060");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL squid packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/09");
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
    'squid-3.5.20-15.el7_8.1',
    'squid-debuginfo-3.5.20-15.el7_8.1',
    'squid-migration-script-3.5.20-15.el7_8.1',
    'squid-sysvinit-3.5.20-15.el7_8.1'
  ],
  'CGSL MAIN 5.04': [
    'squid-3.5.20-15.el7_8.1',
    'squid-debuginfo-3.5.20-15.el7_8.1',
    'squid-migration-script-3.5.20-15.el7_8.1',
    'squid-sysvinit-3.5.20-15.el7_8.1'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid');
}
