##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162321);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2022-22365");
  script_xref(name:"IAVA", value:"2022-A-0232");

  script_name(english:"IBM WebSphere Application Server Spoofing (6587947)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is vulnerable to spoofing.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0, 8.0, 8.5, and 9.0, with the Ajax Proxy Web Application (AjaxProxy.war)
deployed, is vulnerable to spoofing by allowing a man-in-the-middle attacker to spoof SSL server hostnames.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6587947");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server version 8.5.5.22, 9.0.5.13 or later. Alternatively, upgrade to the minimal
fix pack levels required by the interim fix and then apply Interim Fix PH44339.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22365");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var fix = 'Interim Fix PH44339';

var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# Not check available for AjaxProxy.war
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app);

if ('PH44339' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.0.5.13', 'fixed_display' : '9.0.5.13 or ' + fix },
  { 'min_version' : '8.5', 'fixed_version' : '8.5.5.22', 'fixed_display' : '8.5.5.22 or ' + fix },
  { 'min_version' : '8.0', 'max_version' : '8.0.0.15', 'fixed_display' : '8.0.0.15 and ' + fix },
  { 'min_version' : '7.0', 'max_version' : '7.0.0.45', 'fixed_display' : '7.0.0.45 and ' + fix },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
