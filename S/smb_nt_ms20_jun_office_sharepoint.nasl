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
  script_id(137269);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id(
    "CVE-2020-1148",
    "CVE-2020-1177",
    "CVE-2020-1178",
    "CVE-2020-1181",
    "CVE-2020-1183",
    "CVE-2020-1289",
    "CVE-2020-1295",
    "CVE-2020-1297",
    "CVE-2020-1298",
    "CVE-2020-1318",
    "CVE-2020-1320",
    "CVE-2020-1323"
  );
  script_xref(name:"MSKB", value:"4484409");
  script_xref(name:"MSKB", value:"4484414");
  script_xref(name:"MSKB", value:"4484391");
  script_xref(name:"MSKB", value:"4484402");
  script_xref(name:"MSKB", value:"4484400");
  script_xref(name:"MSKB", value:"4484405");
  script_xref(name:"MSFT", value:"MS20-4484409");
  script_xref(name:"MSFT", value:"MS20-4484414");
  script_xref(name:"MSFT", value:"MS20-4484391");
  script_xref(name:"MSFT", value:"MS20-4484402");
  script_xref(name:"MSFT", value:"MS20-4484400");
  script_xref(name:"MSFT", value:"MS20-4484405");
  script_xref(name:"IAVA", value:"2020-A-0251-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An open redirect vulnerability exists in Microsoft
    SharePoint that could lead to spoofing.  (CVE-2020-1323)

  - An elevation of privilege vulnerability exists in
    Microsoft SharePoint. An attacker who successfully
    exploited this vulnerability could attempt to
    impersonate another user of the SharePoint server.
    (CVE-2020-1295)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint Server when it fails to properly
    identify and filter unsafe ASP.Net web controls. An
    authenticated attacker who successfully exploited the
    vulnerability could use a specially crafted page to
    perform actions in the security context of the
    SharePoint application pool process.  (CVE-2020-1181)

  - A cross-site-scripting (XSS) vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted web request to an affected SharePoint
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected SharePoint server. The attacker who
    successfully exploited the vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. The attacks could allow the attacker to read
    content that the attacker is not authorized to read, use
    the victim's identity to take actions on the SharePoint
    site on behalf of the user, such as change permissions
    and delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2020-1177,
    CVE-2020-1183, CVE-2020-1297, CVE-2020-1298,
    CVE-2020-1318, CVE-2020-1320)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted authentication request to an affected
    SharePoint server. An attacker who successfully
    exploited this vulnerability could execute malicious
    code on a vulnerable server in the context of the
    SharePoint application pool account.  (CVE-2020-1178)

  - A spoofing vulnerability exists when Microsoft
    SharePoint Server does not properly sanitize a specially
    crafted web request to an affected SharePoint server. An
    authenticated attacker could exploit the vulnerability
    by sending a specially crafted request to an affected
    SharePoint server. The attacker who successfully
    exploited the vulnerability could then perform cross-
    site scripting attacks on affected systems and run
    script in the security context of the current user.
    These attacks could allow the attacker to read content
    that the attacker is not authorized to read, use the
    victim's identity to take actions on the SharePoint site
    on behalf of the user, such as change permissions and
    delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2020-1148,
    CVE-2020-1289)");
  # https://support.microsoft.com/en-us/help/4484409/security-update-for-sharepoint-foundation-2013-june-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3ed2d30");
  # https://support.microsoft.com/en-us/help/4484414/security-update-for-sharepoint-server-2010-june-9-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25f013bc");
  # https://support.microsoft.com/en-us/help/4484391/security-update-for-sharepoint-foundation-2010-june-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e56f1871");
  # https://support.microsoft.com/en-us/help/4484402/security-update-for-sharepoint-server-2016-june-9-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a150f7d");
  # https://support.microsoft.com/en-us/help/4484400/security-update-for-sharepoint-server-2019-june-9-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f698971");
  # https://support.microsoft.com/en-us/help/4484405/security-update-for-sharepoint-server-2013-june-9-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b403bd01");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484409
  -KB4484414
  -KB4484391
  -KB4484402
  -KB4484400
  -KB4484405");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1295");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS20-06';

kbs = make_list(
  '4484414', # 2010 SP2 Foundation 
  '4484391', # 2010 SP2 Foundation
  '4484405', # 2013 SP1 Enterprise
  '4484409', # 2013 SP1 Foundation
  '4484402', # 2016 Enterprise
  '4484400'  # 2019
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
         'kb'           : '4484391',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\14\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '14.0.7252.5000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP 2'
      }],
    'Server':
      [{
         'kb'           : '4484414',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'microsoft.sharepoint.publishing.dll',
         'version'      : '14.0.7252.5000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP 2'
      }]
    }
  },
  '2013':
  { '1':
    {'Foundation':
      [{
         'kb'           : '4484409',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\15\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '15.0.5249.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      }],
    'Server':
      [{ 
         'kb'           : '4484405',
         'path'         : install['path'],
         'append'       : 'transformapps',
         'file'         : 'docxpageconverter.exe',
         'version'      : '15.0.5249.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      }]
    }
  },
  '2016':
  { '0':
    {'Server':
      [{ 
         'kb'           : '4484402',
         'path'         :  hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\16\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '16.0.5017.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
      }]
    }
  },
  '2019':
  { '0':
    {'Server':
    [ {
         'kb'           : '4484400',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'ascalc.dll',
         'version'      : '16.0.10358.20000',
         'product_name' : 'Microsoft SharePoint Server 2019'
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

  if(are_we_vuln == HCF_OLDER)
  {
    vuln = TRUE;
    if (check['kb'] == '4484391' ||
        check['kb'] == '4484414' ||
        check['kb'] == '4484409' ||
        check['kb'] == '4484402' ||
        check['kb'] == '4484400' 
    ) xss = TRUE;
  }
}

if (vuln)
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  if (xss) replace_kb_item(name:'www/' + port + '/XSS', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
