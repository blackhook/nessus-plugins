#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149481);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2021-22907");
  script_xref(name:"IAVA", value:"2021-A-0242-S");

  script_name(english:"Citrix Workspace App for Windows Security Update Privilege Escalation Vulnerability (CTX307794)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace installed on the remote host is affected by a privilege escalation vulnerability. 
 A local user could escalate their privilege level to SYSTEM on the computer running Citrix Workspace app for Windows.
 This vulnerability only exists if Citrix Workspace app was installed using an account with local or domain administrator 
 privileges. It does not exist when a standard Windows user installed Citrix Workspace app for Windows.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX307794");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace App 1912 LTSR CU4 and later cumulative updates, Citrix Workspace App
2105 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_win_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Citrix Workspace");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::get_app_info(app:'Citrix Workspace');

# Affected versions
# Citrix Workspace app prior to 2105:
# https://www.citrix.com/downloads/workspace-app/windows/workspace-app-for-windows-latest.html
# Citrix Workspace app 1912 LTSR for Windows (before CU4) 
# https://www.citrix.com/downloads/workspace-app/workspace-app-for-windows-long-term-service-release/workspace-app-for-windows-1912ltsr.html
var constraints = [
  { 'min_version' : '18.08.0.0', 'max_version' : '19.11.9999.0', 'fixed_version' : '21.5.0.48' },
  { 'min_version' : '19.12.0.0', 'fixed_version' : '19.12.4000.19' },
  { 'min_version' : '20.02.0.0', 'fixed_version' : '21.5.0.48' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
