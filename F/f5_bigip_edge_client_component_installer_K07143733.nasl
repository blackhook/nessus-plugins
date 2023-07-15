#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(174339);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id("CVE-2023-22283");
  script_xref(name:"IAVA", value:"2023-A-0178");

  script_name(english:"F5 BIG-IP Edge Client Windows Component Installer 7.2.x < 7.2.3.1 DLL Hijacking (K07143733)");

  script_set_attribute(attribute:"synopsis", value:
"A web client installed on the remote Windows host is affected by a DLL hijacking
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Big-IP Edge Client Windows Component Installer installed on the remote Windows
host is 7.2.2.x or 7.2.3.x before 7.2.3.1. It is, therefore, affected by a DLL hijacking vulnerability 
exists in the BIG-IP Edge Client for Windows. User interaction and administrative privileges are 
required to exploit this vulnerability because the victim user needs to run the executable on the 
system and the attacker requires administrative privileges for modifying the files in the trusted 
search path. (CVE-2023-22283)");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K07143733");
  script_set_attribute(attribute:"solution", value:
"Upgrade client software to a version referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:f5:edge_client_component_installer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_big-ip_edge_client_component_installer_win_installed.nbin");
  script_require_keys("installed_sw/F5 Networks BIG-IP Edge Client Component Installer");

  exit(0);
}

include('vcf.inc');
var app, app_info, constraints;

get_kb_item_or_exit('SMB/Registry/Enumerated');

app = 'F5 Networks BIG-IP Edge Client Component Installer';

app_info = vcf::get_app_info(app:app, win_local:TRUE);
app_info.display_version = app_info.display_version + ' (' + app_info.version + ')';

constraints = [
  { 'min_version' : '7220', 'fixed_version' : '7231.2022.1019.458', 'fixed_display' : '7.2.3.1 (7231.2022.1019.458)' }  
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
