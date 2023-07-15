#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144777);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-8743");
  script_bugtraq_id(95077);

  script_name(english:"IBM HTTP Server 7.0.0.0 < 7.0.0.43 / 8.0.0.0 < 8.0.0.14 / 8.5.0.0 < 8.5.5.12 / 9.0.0.0 < 9.0.0.3 Response Splitting (289001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a response splitting attack vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability related to Apache HTTP Server.
Apache HTTP Server, in all releases prior to 2.2.32 and 2.4.25, was liberal in the whitespace accepted from requests and
sent in response lines and headers. Accepting these different behaviors represented a security concern when httpd
participates in any chain of proxies or interacts with back-end application servers, either through mod_proxy or using
conventional CGI mechanisms, and may result in request smuggling, response splitting and cache pollution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/289001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.43, 8.0.0.14, 8.5.5.12, 9.0.0.3, or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply Interim Fix PI82481.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

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
fix = 'Interim Fix PI82481';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI82481' >< app_info['Fixes'] || 'PI73984' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.41', 'fixed_display' : '7.0.0.43 or ' + fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.13', 'fixed_display' : '8.0.0.14 or ' + fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.11', 'fixed_display' : '8.5.5.12 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.2', 'fixed_display' : '9.0.0.3 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
