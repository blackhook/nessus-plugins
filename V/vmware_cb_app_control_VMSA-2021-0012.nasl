#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152047);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/19");

  script_cve_id("CVE-2021-21998");
  script_xref(name:"IAVA", value:"2021-A-0295-S");
  script_xref(name:"VMSA", value:"2021-0012");

  script_name(english:"VMware Carbon Black App Control 8.0.x / 8.1.x / 8.5.x < 8.5.8 / 8.6.x < 8.6.2 Authentication Bypass (VMSA-2021-0012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in the VMware Carbon Black App Control management server. An 
unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary actions with 
administrative privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0012.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Carbon Black App Control 8.5.8, 8.6.2, or later, or apply the relevant hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21998");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:carbon_black_app_control");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "vmware_carbon_black_app_control_win_installed.nbin", "vmware_carbon_black_app_control_web_console_detect.nbin");
  script_require_keys("installed_sw/VMware Carbon Black App Control");

  exit(0);
}

include('vcf.inc');

var app_name = 'VMware Carbon Black App Control';

# logic confirm the asset is windows 
var local_os = get_kb_item('Host/OS');
var reg_enum = get_kb_item('SMB/Registry/Enumerated');
if ((!empty_or_null(local_os) && 'windows' >!< tolower(local_os)) && !reg_enum )
  audit(AUDIT_OS_NOT, 'Windows');

var app_info = vcf::combined_get_app_info(app:app_name);

if (app_info.version =~ "^8\.[10]\." && report_paranoia < 2) 
  audit(AUDIT_POTENTIAL_VULN, 'VMware Carbon Black App Control', app_info.version);

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.2', 'fixed_display' : 'See vendor advisory for Hotfix' },
  { 'min_version' : '8.5.0.0', 'fixed_version' : '8.5.8.4' },
  { 'min_version' : '8.6.0.0', 'fixed_version' : '8.6.2.26' }
];

if (app_info.version =~ "^8\.[10]\." && report_paranoia < 2) 
  audit(AUDIT_POTENTIAL_VULN, 'VMware Carbon Black App Control', app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);