#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178029);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-21564");

  script_name(english:"Azure DevOps Server 2022 XSS ");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps install is missing security updates. It is, therefore,
affected by a cross-site scripting vulnerability.  An attacker who successfully exploited the 
vulnerability could access data that is available for the current user. Depending on the user's 
authorization the attacker could collect detailed data about ADO elements such as org/proj configuration, 
users, groups, teams, projects, pipelines, board, or wiki. An attacker could also craft 
page elements to collect user secrets.

Note that Nessus has not tested for these issues but has instead relied only on
the application's self-reported version number.");
  # https://learn.microsoft.com/en-us/azure/devops/server/release-notes/azuredevops2022?view=azure-devops#azure-devops-server-2022-patch-2-release-date-february-14-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b241a097");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Azure DevOps Server 2022 Patch 2 to address this issue.

Please refer to the vendor guidance to determine the version and patch to
apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21564");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
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

var ado_constraints = [
  {
    'release'        : '2022',
    'update_min_ver' : '0',
    'update_max_ver' : '1.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '19.0.0.0',
    'file_fix_ver'   : '19.205.33417.5',
    'note'           : 'Azure DevOps Server 2022 prior to Azure DevOps Server 2022 Patch 2 is vulnerable. Ensure\n' +
                       'the installation is updated to Azure DevOps Server 2022 Patch 2.\n'
  }
];

vcf::microsoft::azure_devops_server::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS23-02',
  constraints:ado_constraints, 
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);