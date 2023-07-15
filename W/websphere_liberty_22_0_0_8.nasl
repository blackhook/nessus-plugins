##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163771);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-22476");
  script_xref(name:"IAVA", value:"2022-A-0301");

  script_name(english:"IBM WebSphere Application Server Liberty 17.0.0.3 <= 22.0.0.7 Identity Spoofing (6602015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is vulnerable to identity spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server Liberty 17.0.0.3 through 22.0.0.7 and Open Liberty are vulnerable to identity 
spoofing by an authenticated user using a specially crafted request.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6602015");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server Liberty version 22.0.0.8 or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PH47867.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_liberty_detect.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM WebSphere Application Server';
var fix = 'Interim Fix PH47867';
var port = get_http_port(default:9080);

var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if (app_info['Product'] != app + ' Liberty')
  audit(AUDIT_HOST_NOT, app + ' Liberty');

# Remote detection doesn't find fix or config, so require paranoia
if ( report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['Product']);

var constraints = [
 { 'min_version' : '17.0.0.3', 'fixed_version' : '22.0.0.8', 'fixed_display' : '22.0.0.8 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
