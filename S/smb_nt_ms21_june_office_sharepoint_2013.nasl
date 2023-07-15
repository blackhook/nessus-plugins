#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150360);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-26420",
    "CVE-2021-31948",
    "CVE-2021-31950",
    "CVE-2021-31963",
    "CVE-2021-31964",
    "CVE-2021-31965",
    "CVE-2021-31966"
  );
  script_xref(name:"MSKB", value:"5001954");
  script_xref(name:"MSKB", value:"5001962");
  script_xref(name:"MSFT", value:"MS21-5001954");
  script_xref(name:"MSFT", value:"MS21-5001962");
  script_xref(name:"IAVA", value:"2021-A-0277-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2013 (June 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2013 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2013 installation on the remote host is missing security updates. It is, therefore, 
affected by multiple vulnerabilities:

  - Microsoft SharePoint Server Remote Code Execution Vulnerability 
    (CVE-2021-26420, CVE-2021-31963, CVE-2021-31964, CVE-2021-31966)

  - Microsoft SharePoint Server Spoofing Vulnerability (CVE-2021-31948, CVE-2021-31950) 

  - Microsoft SharePoint Server Information Disclosure Vulnerability (CVE-2021-31965)    
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001954");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001962");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5001954
  -KB5001962");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31966");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-31963");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS21-06';
var app_name = 'Microsoft SharePoint Server';
var kbs = make_list(
  '5001954',
  '5001962'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
var windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

var install = get_single_install(app_name:app_name);

var kb_checks =
{
  '2013':
  { '1':
    {'Foundation':
      [{
         'kb'           : '5001962',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\15\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '15.0.5353.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      }],
      'Server':
      [{
         'kb'           : '5001954',
         'path'         : install['path'],
         'append'       : 'webservices\\conversionservices',
         'file'         : 'msoserver.dll',
         'version'      : '15.0.5353.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      }]
    }
  }
};

# Get the specific product / path
var param_list = kb_checks[install['Product']][install['SP']][install['Edition']];
# audit if not affected
if(isnull(param_list)) audit(AUDIT_HOST_NOT, 'affected');
var port = kb_smb_transport();
# grab the path otherwise
foreach check (param_list)
{
  if (!isnull(check['version']))
  {
    var path = check['path'];
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
    var report = '\n';
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
  audit(AUDIT_INST_VER_NOT_VULN, app_name);
}
