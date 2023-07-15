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
  script_id(147753);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-24104", "CVE-2021-27076");
  script_xref(name:"MSKB", value:"4493238");
  script_xref(name:"MSKB", value:"4493177");
  script_xref(name:"MSFT", value:"MS21-4493238");
  script_xref(name:"MSFT", value:"MS21-4493177");
  script_xref(name:"IAVA", value:"2021-A-0136-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2013 (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2013 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2013 installation on the remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities:

  - A session spoofing vulnerability exists. An attacker can exploit this to perform actions with the privileges
    of another user. (CVE-2021-24104)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-27076)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493238");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493177");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4493238
  -KB4493177");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

paranoid_audit = FALSE;

bulletin = 'MS21-03';
app_name = 'Microsoft SharePoint Server';

kbs = make_list(
  '4493238',
  '4493177'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();
install = get_single_install(app_name:app_name);
kb_checks =
{
  '2013':
  { '1':
    {'Foundation':
      [
        {
         'kb'           : '4493238',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\15\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '15.0.5327.1001',
         'product_name' : 'Microsoft SharePoint Foundation 2013 Core'
        },
        {#Language File
         'kb'           : '4493177',
        #'path'         : hotfix_get_commonfilesdir(),
        #'append'       : 'microsoft shared\\server15\\server setup controller',
        #'file'         : 'csisrv.dll',
        #'version'      : '15.0.5233.1000',
         'product_name' : 'Microsoft SharePoint Foundation 2013 Core'
        }
      ]
    }
  }
};

# Get the specific product / path
param_list = kb_checks[install['Product']][install['SP']][install['Edition']];
# audit if not affected
if(isnull(param_list)) audit(AUDIT_HOST_NOT, 'affected');
port = kb_smb_transport();
reg_keys = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
# grab the path otherwise
foreach check (param_list)
{
  if (check['kb'] == '4493177')
  { 
    are_we_vuln = HCF_OLDER;
    foreach display_name (reg_keys)
    {
      if ('KB'+check['kb'] >< display_name)
      {
        are_we_vuln = HCF_OK;
        break;
      }
    }
    if (report_paranoia < 2 && are_we_vuln != HCF_OK)
    {
      paranoid_audit = TRUE;
      are_we_vuln = HCF_OK;
      report = '\n';
      if (check['product_name'])
        report += '  Product : ' + check['product_name'] + '\n';
        report += '  KB : ' + check['kb'] + ' was not confirmed due to Paranoid Check settings \n';
      hotfix_add_report(report, kb:check['kb']);
      break;
    }
  }
  if (!isnull(check['version']))
  {
    path = check['path'];
    if (!empty_or_null(check['append']))
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
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  if (paranoid_audit == TRUE) audit(AUDIT_POTENTIAL_VULN, app_name);
  audit(AUDIT_INST_VER_NOT_VULN, app_name);
}
