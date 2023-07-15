#%NASL_MIN_LEVEL 80900
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177392);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2023-21565", "CVE-2023-21569");
  script_xref(name:"IAVA", value:"2023-A-0308");

  script_name(english:"Security Updates for Microsoft Team Foundation Server and Azure DevOps Server (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps is affected by multiple spoofing vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps install is missing
security updates. It is, therefore, affected by multiple server spoofing vulnerabilities. An attacker who 
successfully exploited the vulnerability could access data that is available for the current user. 
Depending on the user's authorization the attacker could collect detailed data about ADO elements 
such as org/proj configuration, users, groups, teams, projects, pipelines, board, or wiki. 
An attacker could also craft page elements to collect user secrets and is able to manipulate 
DOM model of website adding/removing elements, with crafted script is able to do actions on 
ADO in current user context without user consent or awareness.

Note all systems require a manual process of applying new resource group
tasks. Nessus is unable to detect the state of the tasks at this time.

Note that Nessus has not tested for these issues but has instead relied only on
the application's self-reported version number.");
  # https://devblogs.microsoft.com/devops/june-patches-for-azure-devops-server-2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?818e46ac");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates:
  - Azure DevOps Server 2022.0.1 with patch 1
  - Azure DevOps Server 2022 with patch 4
  - Azure DevOps Server 2020.1.2 with patch 6
  - Azure DevOps Server 2020.0.2 with patch 2
  - Azure DevOps Server 2019.1.2 with patch 3

Please refer to the vendor guidance to determine the version and patch to
apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21565");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl");
  script_require_keys("installed_sw/Microsoft Team Foundation Server");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::azure_devops_server::get_app_info();

# These file_fix versions are stored in both the patch & the registry, use the python script to obtain / extract the value easily
var ado_constraints = [
  {
    'release'        : '2019',
    'update_min_ver' : '1.0',
    'update_max_ver' : '1.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '17.0.0.0',
    'file_fix_ver'   : '17.153.33801.1',
    'note'           : 'Azure DevOps Server 2019 prior to 2019.1.2 patch 3 is vulnerable. Ensure\n' +
                       'the installation is updated to 2019.1.2 patch 3.'
  },
  {
    'release'        : '2020',
    'update_min_ver' : '0',
    'update_max_ver' : '0.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '18.0.0.0',
    'file_fix_ver'   : '18.170.33802.3',
    'note'           : 'Azure DevOps Server 2020 prior to 2020.0.2 patch 2 is vulnerable. Ensure\n' +
                       'the installation is updated to 2020.0.2 patch 2.\n'
  },
  {
    'release'        : '2020',
    'update_min_ver' : '1.0',
    'update_max_ver' : '1.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '18.0.0.0',
    'file_fix_ver'   : '18.181.33801.3',
    'note'           : 'Azure DevOps Server 2020 prior to 2020.1.2 patch 6 is vulnerable. Ensure\n' +
                       'the installation is updated to 2020.1.2 patch 6.\n'
  },
  {
    'release'        : '2022',
    'update_min_ver' : '0',
    'update_max_ver' : '0.1',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '19.0.0.0',
    'file_fix_ver'   : '19.205.33802.4',
    'note'           : 'Azure DevOps Server 2022 prior to 2022 patch 4 is vulnerable. Ensure\n' +
                       'the installation is updated to 2022 patch 4.\n'
  },
  {
    'release'        : '2022',
    'update_min_ver' : '0.1',
    'update_max_ver' : '0.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '19.205.33802.0',
    'file_fix_ver'   : '19.205.33802.5',
    'note'           : 'Azure DevOps Server 2022 prior to 2022.0.1 patch 1 is vulnerable. Ensure\n' +
                       'the installation is updated to 2022.0.1 patch 1.\n'
  }
];

vcf::microsoft::azure_devops_server::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS23-06',
  constraints:ado_constraints, 
  severity:SECURITY_HOLE
);
