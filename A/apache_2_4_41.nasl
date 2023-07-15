#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128033);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-9517",
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10092",
    "CVE-2019-10097",
    "CVE-2019-10098"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Apache 2.4.x < 2.4.41 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.41. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.41 advisory, including the following:

  - A limited cross-site scripting issue was reported affecting the mod_proxy error page. An attacker could
    cause the link on the error page to be malformed and instead point to a page of their choice. This would
    only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way
    that the Proxy Error page was displayed. (CVE-2019-10092)

  - HTTP/2 (2.4.20 through 2.4.39) very early pushes, for example configured with H2PushResource, could lead
    to an overwrite of memory in the pushing request's pool, leading to crashes. The memory copied is that
    of the configured push link header values, not data supplied by the client. (CVE-2019-10081)

  - Some HTTP/2 implementations are vulnerable to unconstrained internal data buffering, potentially leading
    to a denial of service. The attacker opens the HTTP/2 window so the peer can send without constraint;
    however, they leave the TCP window closed so the peer cannot actually write (many of) the bytes on the
    wire. The attacker then sends a stream of requests for a large response object. Depending on how the
    servers queue the responses, this can consume excess memory, CPU, or both. (CVE-2019-9517)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.41 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'min_version' : '2.4.0', 'fixed_version' : '2.4.41', 'modules':['mod_proxy', 'mod_http2', 'mod_remoteip', 'mod_rewrite'] }
];

vcf::apache_http_server::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
