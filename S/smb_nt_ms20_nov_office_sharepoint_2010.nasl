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
  script_id(142808);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-17016",
    "CVE-2020-17017",
    "CVE-2020-17060",
    "CVE-2020-17061"
  );
  script_xref(name:"MSKB", value:"4486744");
  script_xref(name:"MSKB", value:"4486706");
  script_xref(name:"MSFT", value:"MS20-4486744");
  script_xref(name:"MSFT", value:"MS20-4486706");
  script_xref(name:"IAVA", value:"2020-A-0514-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0135");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2010 (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2010 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2010 installation on the
remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities :

  - A Spoofing Vulnerability exists in Microsoft SharePoint. (CVE-2020-17016, CVE-2020-17060)

  - An Information Disclosure Vulnerability exists in Microsoft SharePoint. (CVE-2020-17017)

  - A Remote Code Execution Vulnerability exists in Microsoft SharePoint. (CVE-2020-17061)");
  # https://support.microsoft.com/en-us/help/4486744/security-update-for-sharepoint-foundation-2010-nov-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69050920");
  # https://support.microsoft.com/en-us/help/4486706/security-update-for-sharepoint-server-2010-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5097f4d7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4486744
  -KB4486706");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');
include('lists.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-11';

kbs = make_list(
  '4486706',
  '4484531',
  '4486708'
  );

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

install = get_single_install(app_name:'Microsoft SharePoint Server');

kb_checks =
{
  '2010':
  { '2': 
    {'Foundation':
      [{
         'kb'           : '4486744',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\14\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '14.0.7262.5000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP 2'
      }],
    'Server':
      [{
         'kb'           : '4486706',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'microsoft.sharepoint.publishing.dll',
         'version'      : '14.0.7262.5000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP 2'
      }]
    }
  }
};

# Get the specific product / path 
param_list = kb_checks[install['Product']][install['SP']][install['Edition']];

# audit if not affected
if(isnull(param_list)) audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft SharePoint Server');

vuln = FALSE;
xss = FALSE;
port = kb_smb_transport();

# grab the path otherwise
foreach check (param_list)
{
 
  if (!isnull(check['version']))
  {
    path = hotfix_append_path(path:check['path'], value:check['append']);

    are_we_vuln = hotfix_check_fversion(
      file:check['file'],
      version:check['version'],
      path:path,
      kb:check['kb'],
      product:check['product_name']
    );
  }
  else
  {
    report = '\n';

    if (check['product_name'])
      report += '  Product : ' + check['product_name'] + '\n';
    if (check['kb'])
      report += '  KB : ' + check['kb'] + '\n';
    hotfix_add_report(report, kb:check['kb']);
  }

  if(are_we_vuln == HCF_OLDER) vuln = TRUE;
}

if (vuln)
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}


