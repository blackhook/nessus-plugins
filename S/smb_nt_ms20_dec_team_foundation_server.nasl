#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143568);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-1325", "CVE-2020-17135", "CVE-2020-17145");

  script_name(english:"Security Updates for Microsoft Team Foundation Server and Azure DevOps Server (December 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps is affected by multiple spoofing vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps install is missing security updates. It is, therefore, affected by
multiple spoofing vulnerabilities. An attacker can exploit these to perform actions with the privileges of another user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://devblogs.microsoft.com/devops/december-patches-for-azure-devops-server-and-team-foundation-server/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?164aac14");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2015 Update 4.2 with patch 7
  - Team Foundation Server 2017 Update 3.1 with patch 12
  - Team Foundation Server 2018 Update 1.2 with patch 9
  - Team Foundation Server 2018 Update 3.2 with patch 14
  - Azure DevOps Server 2019 Update 0.1 with patch 9
  - Azure DevOps Server 2019 Update 1.1 with patch 6
  - Azure DevOps Server 2020 with patch 1

Please refer to the vendor guidance to determine the version and patch to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1325");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17145");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl");
  script_require_keys("installed_sw/Microsoft Team Foundation Server");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::azure_devops_server::get_app_info();

var ado_constraints = [
  {
    'release'        : '2015',
    'update_min_ver' : '0',
    'update_max_ver' : '4.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '14.0.0.0',
    'file_fix_ver'   : '14.114.30730.0',
    'note'           : 'Team Foundation Server 2015 prior to Update 4.2 patch 7 is vulnerable. Ensure\n' +
                       'the installation is updated to Update 4.2 patch 7'
  },
  {
    'release'        : '2017',
    'update_min_ver' : '0',
    'update_max_ver' : '3.1',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
    'file_min_ver'   : '15.0.0.0',
    'file_fix_ver'   : '15.117.30801.0',
    'note'           : 'Team Foundation Server 2017 prior to Update 3.1 patch 12 is vulnerable. Ensure\n' +
                      'the installation is updated to Update 3.1 patch 12'
  },
  {
    'release'        : '2018',
    'update_min_ver' : '0',
    'update_max_ver' : '1.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
    'file_min_ver'   : '16.0.0.0',
    'file_fix_ver'   : '16.122.30723.1',
    'note'           : 'Team Foundation Server 2018 prior to Update 1.2 patch 9 is vulnerable. Ensure\n' +
                       'the installation is updated to Update 1.2 patch 9'
  },
  {
    'release'        : '2018',
    'update_min_ver' : '2',
    'update_max_ver' : '3.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.WorkItemTracking.Web.dll',
    'file_min_ver'   : '16.0.0.0',
    'file_fix_ver'   : '16.131.30724.3',
    'note'           : 'Team Foundation Server 2018 prior to Update 3.2 patch 14 is vulnerable. Ensure\n' +
                      'the installation is updated to Update 3.2 patch 14',
  },
  {
    'release'        : '2019',
    'update_min_ver' : '0',
    'update_max_ver' : '0.1',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '17.0.0.0',
    'file_fix_ver'   : '17.143.30723.4',
    'note'           : 'Azure DevOps Server 2019 prior to 2019.0.1 patch 9 is vulnerable. Ensure\n' +
                       'the installation is updated to 2019.0.1 patch 9.'
  },  
  {
    'release'        : '2019',
    'update_min_ver' : '1.0',
    'update_max_ver' : '1.1',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.VisualStudio.Services.Feed.Server.dll',
    'file_min_ver'   : '17.0.0.0',
    'file_fix_ver'   : '17.153.30723.5',
    'note'           : 'Azure DevOps Server 2019 prior to 2019.1.1 patch 6 is vulnerable. Ensure\n' +
                       'the installation is updated to 2019.1.1 patch 6.'
  },
  {
    'release'        : '2020',
    'update_min_ver' : '0',
    'update_max_ver' : '0',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '18.0.0.0',
    'file_fix_ver'   : '18.170.30723.6',
    'note'           : 'Azure DevOps Server 2020 prior to 2020 patch 1 is vulnerable. Ensure\n' +
                       'the installation is updated to 2020 patch 1.'
  }
];

vcf::microsoft::azure_devops_server::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS20-12',
  constraints:ado_constraints, 
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
