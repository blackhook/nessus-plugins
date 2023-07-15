#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000132539.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(175792);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2023-24461");
  script_xref(name:"IAVA", value:"2023-A-0237");

  script_name(english:"F5 BIG-IP Edge Client Windows Component Installer < 7.2.4.1 Improper Certificate Validation (K000132539)");

  script_set_attribute(attribute:"synopsis", value:
"A web client installed on the remote Windows host is affected by an improper certificate validation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Big-IP Edge Client Windows Component Installer installed on the remote Windows
host is before 7.2.4.1. An improper certificate validation vulnerability exists in BIG-IP Edge Client 
for Windows and macOS and may allow an attacker to impersonate a BIG-IP APM system. (CVE-2023-24461)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000132539");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000132539.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

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

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app = 'F5 Networks BIG-IP Edge Client Component Installer';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);
app_info.display_version = app_info.display_version + ' (' + app_info.version + ')';

# Fixed display here https://techdocs.f5.com/kb/en-us/products/big-ip_apm/releasenotes/related/relnote-edge-client-7-2-4-1.html
var constraints = [
  { 'min_version' : '7220', 'fixed_version' : '7241.2023.331.1108', 'fixed_display' : '7.2.4.1 (7241.2023.331.1108)' }  
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
