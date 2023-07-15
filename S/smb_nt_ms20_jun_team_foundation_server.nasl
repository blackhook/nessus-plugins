#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(137270);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id("CVE-2020-1327");

  script_name(english:"Security Updates for Microsoft Team Foundation Server (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server is affected by an HTML injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server is missing security updates. It is, therefore, affected by an HTML injection
vulnerability due to not properly sanitizing user inputs. An unauthenticated, remote attacker can exploit this to
perform script or content injection attacks, which could trick a user into disclosing sensitive information.");
  # https://devblogs.microsoft.com/devops/june-patches-for-azure-devops-server-and-team-foundation-server/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6ee4c5f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2017 Update 3.1 with patch 11
  - Team Foundation Server 2018 Update 3.2 with patch 11
  - Azure DevOps Server 2019 Update 0.1 with patch 6
  - Azure DevOps Server 2019 Update 1.1 with patch 3

Please refer to the vendor guidance to determine the version and patch to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');
include('spad_log_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-06';

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

port = kb_smb_transport();

installs = get_installs(app_name:'Microsoft Team Foundation Server', exit_if_not_found:TRUE);

foreach install (installs[1])
{
  vuln = FALSE;
  xss = FALSE;
  path = install['path'];
  update = install['Update'];
  release = install['Release'];

  spad_log(message: 'path: ' + path + '\n update: ' + update + '\n release: ' + release);
  # Those without update mappings
  if (empty_or_null(update) || !release)
    audit(AUDIT_HOST_NOT, 'affected');
  if (release == '2017' && ver_compare(ver:update, fix:'3.1', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
                              version:'15.117.30128.0',
                              min_version:'15.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2017 Update 3.1') == HCF_OLDER)
    {
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2017 prior to Update 3.1 patch 11 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 3.1 patch 11', bulletin:bulletin);
    }
  }
  # 2018 Update 2 -> 2018 Update 3.2 (131)
  else if (release == '2018' && ver_compare(ver:update, fix:'3.2', minver:'2', strict:FALSE) <= 0 
    && !isnull(ver_compare(ver:update, fix:'3.2', minver:'2', strict:FALSE)))
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Web.dll',
                              version:'16.131.30128.10',
                              min_version:'16.131.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2018 Update 3.2') == HCF_OLDER)
    {
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2018 prior to Update 3.2 patch 11 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 3.2 patch 11', bulletin:bulletin);
     }
  }
  else if (release == '2019' && ver_compare(ver:update, fix:'0.1', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Server.DataServices.dll',
                              version:'17.143.30129.2',
                              min_version:'17.0.0.0',
                              path:path,
                              product:'Microsoft Azure DevOps Server 2019.0.1') == HCF_OLDER)
    {
      vuln = TRUE;
      hotfix_add_report('Azure DevOps Server 2019 prior to 2019.0.1 patch 6 is vulnerable. Ensure\n' +
                        'the installation is updated to 2019.0.1 patch 6.', bulletin:bulletin);
    }
  }
  else if (release == '2019' && ver_compare(ver:update, fix:'1.1', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.VisualStudio.Services.Feed.Server.dll',
                              version:'17.153.30128.8',
                              min_version:'17.0.0.0',
                              path:path,
                              product:'Microsoft Azure DevOps Server 2019.1.1') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Azure DevOps Server 2019 prior to 2019.1.1 patch 3 is vulnerable. Ensure\n' +
                        'the installation is updated to 2019.1.1 patch 3.', bulletin:bulletin);
    }
  }
}

if (vuln)
{
  if (xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
