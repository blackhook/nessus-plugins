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
  script_id(134380);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-0700", "CVE-2020-0758", "CVE-2020-0815");
  script_xref(name:"IAVA", value:"2020-A-0096-S");

  script_name(english:"Security Updates for Microsoft Team Foundation Server (March 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server is missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - A Cross-site Scripting (XSS) vulnerability exists when
    Azure DevOps Server does not properly sanitize user
    provided input. An authenticated attacker could exploit
    the vulnerability by sending a specially crafted payload
    to the Team Foundation Server, which will get executed
    in the context of the user every time a user visits the
    compromised page. The attacker who successfully
    exploited the vulnerability could then perform cross-
    site scripting attacks on affected systems and run
    script in the security context of the current user. The
    attacks could allow the attacker to read content that
    the attacker is not authorized to read, execute
    malicious code, and use the victim's identity to take
    actions on the site on behalf of the user, such as
    change permissions and delete content. The security
    update addresses the vulnerability by ensuring that
    Azure DevOps Server sanitizes user inputs.
    (CVE-2020-0700)

  - An elevation of privilege vulnerability exists when
    Azure DevOps Server and Team Foundation Services
    improperly handle pipeline job tokens. An attacker who
    successfully exploited this vulnerability could extend
    their access to a project.  (CVE-2020-0758,
    CVE-2020-0815)");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2017 Update 3.1 with patch 10
  - Team Foundation Server 2018 Update 1.2 with patch 8
  - Team Foundation Server 2018 Update 3.2 with patch 10
  - Azure DevOps Server 2019 Update 0.1 with patch 5
  - Azure DevOps Server 2019 Update 1.1 with patch 1

Please refer to the vendor guidance to determine the version and patch
to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0815");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');
include('spad_log_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-03';

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
                              version:'15.117.29825.0',
                              min_version:'15.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2017 Update 3.1') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2017 prior to Update 3.1 patch 10 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 3.1 patch 10', bulletin:bulletin);
    }
  }
  # 2018 RTW -> 2018 Update 1.2 (122)
  else if (release == '2018' && ver_compare(ver:update, fix:'1.2', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
                              version:'16.122.29825.4',
                              min_version:'16.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2018 Update 1.2') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2018 prior to Update 1.2 patch 8 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 1.2 patch 8', bulletin:bulletin);
     }
  }
  # 2018 Update 2 -> 2018 Update 3.2 (131)
  else if (release == '2018' && ver_compare(ver:update, fix:'3.2', minver:'2', strict:FALSE) <= 0
    && !isnull(ver_compare(ver:update, fix:'3.2', minver:'2', strict:FALSE)))
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Web.dll',
                              version:'16.131.29825.3',
                              min_version:'16.131.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2018 Update 3.2') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2018 prior to Update 3.2 patch 9 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 3.2 patch 9', bulletin:bulletin);
     }
  }
  else if (release == '2019' && ver_compare(ver:update, fix:'0.1', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Server.DataServices.dll',
                              version:'17.143.29825.2',
                              min_version:'17.0.0.0',
                              path:path,
                              product:'Microsoft Azure DevOps Server 2019.0.1') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Azure DevOps Server 2019 prior to 2019.0.1 patch 5 is vulnerable. Ensure\n' +
                        'the installation is updated to 2019.0.1 patch 5.', bulletin:bulletin);
    }
  }
  else if (release == '2019' && ver_compare(ver:update, fix:'1.1', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.VisualStudio.Services.Feed.Server.dll',
                              version:'17.153.29904.2',
                              min_version:'17.0.0.0',
                              path:path,
                              product:'Microsoft Azure DevOps Server 2019.1.1') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Azure DevOps Server 2019 prior to 2019.1.1 patch 1 is vulnerable. Ensure\n' +
                        'the installation is updated to 2019.1.1 patch 1.', bulletin:bulletin);
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
