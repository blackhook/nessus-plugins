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
  script_id(135758);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2020-0954");
  script_xref(name:"MSKB", value:"4462153");
  script_xref(name:"MSFT", value:"MS20-4462153");

  script_name(english:"Security Updates for Microsoft Project Server (April 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project Server installation on the remote host is missing a security update. It is, therefore, affected 
by a cross-site-scripting (XSS) vulnerability. Microsoft SharePoint Server does not properly sanitize a specially
crafted web request to an affected SharePoint server. An authenticated attacker could exploit the vulnerability by
sending a specially crafted request to an affected SharePoint server. The attacker who successfully exploited the
vulnerability could then perform cross-site scripting attacks on affected systems and run scripts in the security
context of the current user. The attacks could allow the attacker to read content that the attacker is not authorized to
read, use the victim's identity to take actions on the SharePoint site on behalf of the user, such as change permissions
and delete content, and inject malicious content in the browser of the user.");
  # https://support.microsoft.com/en-us/help/4462153/security-update-for-project-server-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?995fbcfd");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4462153 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0954");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_project_installed.nbin");
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
include('lists.inc');

global_var vuln;

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-04';

kbs = make_list('4462153'); # Project Server 2013 SP1

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# 64-bit only
arch = get_kb_item_or_exit('SMB/ARCH');
if (isnull(arch) || "x64" >!< arch) audit(AUDIT_HOST_NOT, 'affected');

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

vuln = FALSE;
port = kb_smb_transport();

install = get_single_install(app_name:'Microsoft Project Server');

# direct reference lookup of product...
kb_checks =
{
  '2013':
  # direct reference lookup of SP...
  { '1':
    [{
      'kb': '4462153',
      'path': install['path'],
      'append':'bin',
      'file':'schedengine.exe',
      'version':'15.0.5233.1000',
      'min_version':'15.0.0.0',
      'product_name':'Microsoft Project Server 2013 SP1'
    }]
  }
};

# get the specific product / path 
param_list = kb_checks[install['Product']][install['SP']];

# audit if not affected
if(isnull(param_list)) audit(AUDIT_INST_VER_NOT_VULN, "Microsoft Project Server");

vuln = FALSE;

foreach check (param_list)
{
  are_we_vuln = hotfix_check_fversion(
    file:check['file'],
    version:check['version'],
    path:check['path'],
    kb:check['kb'],
    product:check['product_name']
  );

  if (are_we_vuln == HCF_OLDER)
      vuln = TRUE;
}

if (vuln == TRUE)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
