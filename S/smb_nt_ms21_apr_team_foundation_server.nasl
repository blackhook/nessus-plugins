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
  script_id(148714);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-27067", "CVE-2021-28459");
  script_xref(name:"IAVA", value:"2021-A-0178");

  script_name(english:"Security Updates for Microsoft Team Foundation Server and Azure DevOps Server (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps install is missing
security updates. It is, therefore, affected by multiple vulnerabilities. An
attacker can exploit these to either perform actions with the privileges of
another user or disclose sensitive information.

Note all systems require a manual process of applying new resource group
tasks. Nessus is unable to detect the state of the tasks at this time.

Note that Nessus has not tested for these issues but has instead relied only on
the application's self-reported version number.");
  # https://devblogs.microsoft.com/devops/april-patches-for-azure-devops-server-and-team-foundation-server-2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba9d476a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates:
  - Azure DevOps Server 2019 Update 1.1 with patch 8
  - Azure DevOps Server 2020 Update 0.1 with patch 2

Additionally, Team Foundation Server 2017 Update 3.1 through Azure DevOps
2020.0.1 require resource group task(s) to be manually applied.

Please refer to the vendor guidance to determine the version and patch to
apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28459");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-27067");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

var manual_note = 'Team Foundation Server requires a manual patch which cannot\n' +
                  'be verified by Nessus. Please verify the patch is installed correctly.';

var ado_constraints = [
  {
    'release'        : '2017',
    'update_min_ver' : '0',
    'update_max_ver' : '3.1',
    'manual_note'    : manual_note
  },
  {
    'release'        : '2018',
    'update_min_ver' : '0',
    'update_max_ver' : '1.2',
    'manual_note'    : manual_note
  },
  {
    'release'        : '2018',
    'update_min_ver' : '2.0',
    'update_max_ver' : '3.2',
    'manual_note'    : manual_note
  },
  {
    'release'        : '2019',
    'update_min_ver' : '0',
    'update_max_ver' : '0.1',
    'manual_note'    : manual_note
  },
  {
    'release'        : '2019',
    'update_min_ver' : '1.0',
    'update_max_ver' : '1.1',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.VisualStudio.Services.Feed.Server.dll',
    'file_min_ver'   : '17.0.0.0',
    'file_fix_ver'   : '17.153.31129.2',
    'note'           : 'Azure DevOps Server 2019 prior to 2019.1.1 patch 8 is vulnerable. Ensure\n' +
                       'the installation is updated to 2019.1.1 patch 8.',
    'manual_note'    : manual_note
  },
  {
    'release'        : '2020',
    'update_min_ver' : '0',
    'update_max_ver' : '0.1',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '18.0.0.0',
    'file_fix_ver'   : '18.170.31123.3',
    'note'           : 'Azure DevOps Server 2020 prior to 2020.0.1 patch 2 is vulnerable. Ensure\n' +
                       'the installation is updated to 2020.0.1 patch 2.\n',
    'manual_note'    : manual_note
  }
];

vcf::microsoft::azure_devops_server::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS21-04',
  constraints:ado_constraints, 
  severity:SECURITY_WARNING
);
