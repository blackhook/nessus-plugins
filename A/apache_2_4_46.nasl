#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139574);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-9490", "CVE-2020-11984", "CVE-2020-11993");
  script_xref(name:"IAVA", value:"2020-A-0376-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Apache 2.4.x < 2.4.46 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.46. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.46 advisory.

  - Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info
    disclosure and possible RCE (CVE-2020-11984)

  - Apache HTTP Server versions 2.4.20 to 2.4.43 When
    trace/debug was enabled for the HTTP/2 module and on
    certain traffic edge patterns, logging statements were
    made on the wrong connection, causing concurrent use of
    memory pools. Configuring the LogLevel of mod_http2
    above info will mitigate this vulnerability for
    unpatched servers. (CVE-2020-11993)

  - Apache HTTP Server versions 2.4.20 to 2.4.43. A
    specially crafted value for the 'Cache-Digest' header in
    a HTTP/2 request would result in a crash when the server
    actually tries to HTTP/2 PUSH a resource afterwards.
    Configuring the HTTP/2 feature via H2Push off will
    mitigate this vulnerability for unpatched servers.
    (CVE-2020-9490)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.46 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11984");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'min_version' : '2.4.20', 'fixed_version' : '2.4.46', 'modules':['mod_proxy_uwsgi', 'mod_http2'] }
];

vcf::apache_http_server::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

