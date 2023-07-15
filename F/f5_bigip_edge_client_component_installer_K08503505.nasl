#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151021);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/06");

  script_cve_id("CVE-2021-23022");
  script_xref(name:"IAVA", value:"2021-A-0289-S");

  script_name(english:"F5 BIG-IP Edge Client Windows Component Installer 7.2.1 < 7.2.1.3 / 7.1.6 < 7.1.9.9 Update 1 Privilege Escalation (K08503505)");

  script_set_attribute(attribute:"synopsis", value:
"A web client installed on the remote Windows host is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Big-IP Edge Client Windows Component Installer installed on
the remote Windows host is 7.2.1 before 7.2.1.3, or between 7.1.6 and 7.1.9.9
Update 1. It is, therefore, affected by a privilege escalation vulnerability. A
local attacker can exploit this to gain privileged or administrator access to
the system.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K08503505");
  script_set_attribute(attribute:"solution", value:
"Upgrade client software to a version referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:f5:edge_client_component_installer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '7210', 'fixed_version' : '7213.2021.527.649', 'fixed_display' : '7.2.1.3 (7213.2021.527.649)' },
  { 'min_version' : '7160', 'fixed_version' : '7199.2021.527.907', 'fixed_display' : '7.1.9.9 (7199.2021.527.907)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
