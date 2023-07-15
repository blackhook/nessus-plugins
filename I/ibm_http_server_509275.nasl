#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144289);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231"
  );
  script_bugtraq_id(
    66550,
    68678,
    68742,
    68745
  );

  script_name(english:"IBM HTTP Server 8.5.0.0 <= 8.5.5.2 / 8.0.0.0 <= 8.0.0.9 / 7.0.0.0 <= 7.0.0.33 / 6.1.0.0. <= 6.1.0.47 / 6.0.2.0 <= 6.0.2.43 Multiple Vulnerabilities (509275)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by multiple vulnerabilities, as follows:

  - Race condition in the mod_status module in the Apache HTTP Server before 2.4.10 allows remote attackers to
cause a denial of service (heap-based buffer overflow), or possibly obtain sensitive credential
information or execute arbitrary code, via a crafted request that triggers improper scoreboard handling
within the status_handler function in modules/generators/mod_status.c and the lua_ap_scoreboard_worker
function in modules/lua/lua_request.c. (CVE-2014-0226)

  - The mod_cgid module in the Apache HTTP Server before 2.4.10 does not have a timeout mechanism, which
allows remote attackers to cause a denial of service (process hang) via a request to a CGI script that
does not read from its stdin file descriptor. (CVE-2014-0231)

  - The deflate_in_filter function in mod_deflate.c in the mod_deflate module in the Apache HTTP Server before
2.4.10, when request body decompression is enabled, allows remote attackers to cause a denial of service
(resource consumption) via crafted request data that decompresses to a much larger size. (CVE-2014-0118)

  - The mod_headers module in the Apache HTTP Server 2.2.22 allows remote attackers to bypass 'RequestHeader
unset' directives by placing a header in the trailer portion of data sent with chunked transfer coding.
NOTE: the vendor states 'this is not a security issue in httpd as such.' (CVE-2013-5704)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/509275");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.4, 8.0.0.10, 7.0.0.35 or later. Alternatively, upgrade to the minimal fix pack
level required by the interim fix and then apply Interim Fix PI22070.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)");

  exit(0);
}

include('vcf.inc');

app = 'IBM HTTP Server (IHS)';
fix = 'Interim Fix PI22070';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

 if ('PI22070' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.2', 'fixed_display' : '8.5.5.4 or Interim Fix PI22070'},
  { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.9', 'fixed_display' : '8.0.0.10 or Interim Fix PI22070'},
  { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.33', 'fixed_display' : '7.0.0.35 or Interim Fix PI22070'},
  { 'min_version' : '6.1.0.0.', 'max_version' : '6.1.0.47', 'fixed_display' : 'Interim Fix PI22070'},
  { 'min_version' : '6.0.2.0', 'max_version' : '6.0.2.43', 'fixed_display' : 'Interim Fix PI22070'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
