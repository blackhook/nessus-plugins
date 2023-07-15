#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-1001. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174760);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/26");

  script_cve_id(
    "CVE-2018-17189",
    "CVE-2018-17199",
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10092",
    "CVE-2020-1927",
    "CVE-2020-11993",
    "CVE-2021-26690",
    "CVE-2021-26691",
    "CVE-2021-39275",
    "CVE-2021-44790",
    "CVE-2022-22720"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL MAIN 6.06 : httpd Multiple Vulnerabilities (NS-SA-2023-1001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.06, has httpd packages installed that are affected by multiple
vulnerabilities:

  - In Apache HTTP server versions 2.4.37 and prior, by sending request bodies in a slow loris way to plain
    resources, the h2 stream for that request unnecessarily occupied a server thread cleaning up that incoming
    data. This affects only HTTP/2 (mod_http2) connections. (CVE-2018-17189)

  - In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session expiry time before
    decoding the session. This causes session expiry time to be ignored for mod_session_cookie sessions since
    the expiry time is loaded when the session is decoded. (CVE-2018-17199)

  - A vulnerability was found in Apache HTTP Server 2.4.17 to 2.4.38. Using fuzzed network input, the http/2
    request handling could be made to access freed memory in string comparison when determining the method of
    a request and thus process the request incorrectly. (CVE-2019-0196)

  - A vulnerability was found in Apache HTTP Server 2.4.34 to 2.4.38. When HTTP/2 was enabled for a http: host
    or H2Upgrade was enabled for h2 on a https: host, an Upgrade request from http/1.1 to http/2 that was not
    the first request on a connection could lead to a misconfiguration and crash. Server that never enabled
    the h2 protocol or that only enabled it for https: and did not set H2Upgrade on are unaffected by this
    issue. (CVE-2019-0197)

  - HTTP/2 (2.4.20 through 2.4.39) very early pushes, for example configured with H2PushResource, could lead
    to an overwrite of memory in the pushing request's pool, leading to crashes. The memory copied is that of
    the configured push link header values, not data supplied by the client. (CVE-2019-10081)

  - In Apache HTTP Server 2.4.18-2.4.39, using fuzzed network input, the http/2 session handling could be made
    to read memory after being freed, during connection shutdown. (CVE-2019-10082)

  - In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the
    mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point
    to a page of their choice. This would only be exploitable where a server was set up with proxying enabled
    but was misconfigured in such a way that the Proxy Error page was displayed. (CVE-2019-10092)

  - Apache HTTP Server versions 2.4.20 to 2.4.43 When trace/debug was enabled for the HTTP/2 module and on
    certain traffic edge patterns, logging statements were made on the wrong connection, causing concurrent
    use of memory pools. Configuring the LogLevel of mod_http2 above info will mitigate this vulnerability
    for unpatched servers. (CVE-2020-11993)

  - In Apache HTTP Server 2.4.0 to 2.4.41, redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an an unexpected URL within
    the request URL. (CVE-2020-1927)

  - Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can
    cause a NULL pointer dereference and crash, leading to a possible Denial Of Service (CVE-2021-26690)

  - In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server
    could cause a heap overflow (CVE-2021-26691)

  - ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules
    pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache
    HTTP Server 2.4.48 and earlier. (CVE-2021-39275)

  - A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser
    (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the
    vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and
    earlier. (CVE-2021-44790)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-1001");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-17189");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-17199");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-0196");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-0197");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-10081");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-10082");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-10092");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-11993");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-1927");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-26690");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-26691");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-39275");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-44790");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22720");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22720");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.06');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.06': [
    'httpd-2.4.37-47.0.1.zncgsl6'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd');
}
