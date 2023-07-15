#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158562);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2021-39038");
  script_xref(name:"IAVA", value:"2022-A-0094-S");

  script_name(english:"IBM WebSphere Application Server Liberty 17.0.0.3 < 22.0.0.3 Clickjacking (6559044)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is vulnerable to clickjacking.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server Liberty running on the remote host is 17.0.0.3 prior to 22.0.0.3. It is,
therefore, affected by a clickjacking vulnerability. By persuading a victim to visit a malicious Web site, a remote
attacker could exploit this vulnerability to hijack the victim's click actions and possibly launch further attacks
against the victim.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6559044");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server Liberty version 22.0.0.3 or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PH43223.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_liberty_detect.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM WebSphere Application Server';
var fix = 'Interim Fix PH43223';
var port = get_http_port(default:9080);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if (app_info['Product'] != app + ' Liberty')
  audit(AUDIT_HOST_NOT, app + ' Liberty');

# Remote detection doesn't find fix or config, so require paranoia
if ( report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['Product']);

var constraints = [
 { 'min_version' : '17.0.0.3', 'fixed_version' : '22.0.0.2', 'fixed_display' : '22.0.0.3 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
