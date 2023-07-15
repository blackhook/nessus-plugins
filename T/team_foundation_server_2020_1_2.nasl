#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171605);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-21553");
  script_xref(name:"IAVA", value:"2023-A-0175-S");

  script_name(english:"Microsoft Team Foundation Server and Azure DevOps Server 2020 RCE ");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps is affected by an RCE vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps install is missing security updates. It is, therefore,
affected by a remote code execution vulnerability.
Note all systems require a manual process of applying new resource group
tasks. Nessus is unable to detect the state of the tasks at this time.
Note that Nessus has not tested for these issues but has instead relied only on
the application's self-reported version number.");
  # https://learn.microsoft.com/en-us/azure/devops/server/release-notes/azuredevops2020u1?view=azure-devops
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b57fc15");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates:
  - Azure DevOps Server 2020 Update 1.2 with patch 5
Please refer to the vendor guidance to determine the version and patch to
apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21553");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl");
  script_require_keys("installed_sw/Microsoft Team Foundation Server");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::azure_devops_server::get_app_info();

var manual_note = 'Team Foundation Server requires a manual patch which cannot\n' +
                  'be verified by Nessus. Please verify the patch is installed correctly.';

var ado_constraints = [
  {
    'release'        : '2020',
    'update_min_ver' : '0',
    'update_max_ver' : '1.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '18.0.0.0',
    'file_fix_ver'   : '18.181.33407.1',
    'note'           : 'Azure DevOps Server 2020 prior to 2020.1.2 patch 5 is vulnerable. Ensure\n' +
                       'the installation is updated to 2020.1.2 patch 5.\n',
    'manual_note'    : manual_note
  }
];

vcf::microsoft::azure_devops_server::check_version_and_report
(
  app_info:app_info,
  constraints:ado_constraints, 
  severity:SECURITY_HOLE
);