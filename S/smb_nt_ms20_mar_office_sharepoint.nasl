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
  script_id(134378);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2020-0795",
    "CVE-2020-0850",
    "CVE-2020-0852",
    "CVE-2020-0891",
    "CVE-2020-0892",
    "CVE-2020-0893",
    "CVE-2020-0894"
  );
  script_xref(name:"MSKB", value:"4484150");
  script_xref(name:"MSKB", value:"4484272");
  script_xref(name:"MSKB", value:"4484282");
  script_xref(name:"MSKB", value:"4484275");
  script_xref(name:"MSKB", value:"4484271");
  script_xref(name:"MSKB", value:"4484197");
  script_xref(name:"MSKB", value:"4484277");
  script_xref(name:"MSKB", value:"4484124");
  script_xref(name:"MSKB", value:"4475606");
  script_xref(name:"MSKB", value:"4475597");
  script_xref(name:"MSFT", value:"MS20-4484150");
  script_xref(name:"MSFT", value:"MS20-4484272");
  script_xref(name:"MSFT", value:"MS20-4484282");
  script_xref(name:"MSFT", value:"MS20-4484275");
  script_xref(name:"MSFT", value:"MS20-4484271");
  script_xref(name:"MSFT", value:"MS20-4484197");
  script_xref(name:"MSFT", value:"MS20-4484277");
  script_xref(name:"MSFT", value:"MS20-4484124");
  script_xref(name:"MSFT", value:"MS20-4475606");
  script_xref(name:"MSFT", value:"MS20-4475597");

  script_name(english:"Security Updates for Microsoft SharePoint Server (March 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - This vulnerability is caused when SharePoint Server does
    not properly sanitize a specially crafted request to an
    affected SharePoint server. An authenticated attacker
    could exploit this vulnerability by sending a specially
    crafted request to an affected SharePoint server. The
    attacker who successfully exploited this vulnerability
    could then perform cross-site scripting attacks on
    affected systems and run script in the security context
    of the current user. These attacks could allow the
    attacker to read content that the attacker is not
    authorized to read, use the victim's identity to take
    actions on the SharePoint site on behalf of the victim,
    such as change permissions, delete content, steal
    sensitive information (such as browser cookies) and
    inject malicious content in the browser of the victim.
    For this vulnerability to be exploited, a user must
    click a specially crafted URL that takes the user to a
    targeted SharePoint Web App site. In an email attack
    scenario, an attacker could exploit the vulnerability by
    sending an email message containing the specially
    crafted URL to the user of the targeted Sharepoint Web
    App site and convincing the user to click the specially
    crafted URL.  (CVE-2020-0795, CVE-2020-0891)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-0850,
    CVE-2020-0892)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-0852)

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
    Server properly sanitizes web requests. (CVE-2020-0893,
    CVE-2020-0894)");
  # https://support.microsoft.com/en-us/help/4484150/security-update-for-sharepoint-server-2013-march-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eccb4bd2");
  # https://support.microsoft.com/en-us/help/4484272/security-update-for-sharepoint-server-2016-march-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94f61ecb");
  # https://support.microsoft.com/en-us/help/4484282/security-update-for-sharepoint-foundation-2013-march-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7300d1c");
  # https://support.microsoft.com/en-us/help/4484275/security-update-for-sharepoint-server-2016-march-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b4cb48");
  # https://support.microsoft.com/en-us/help/4484271/security-update-for-sharepoint-server-2019-march-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81543a06");
  # https://support.microsoft.com/en-us/help/4484197/security-update-for-sharepoint-foundation-2010-march-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edfa5253");
  # https://support.microsoft.com/en-us/help/4484277/security-update-for-sharepoint-server-2019-language-pack
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c5091a1");
  # https://support.microsoft.com/en-us/help/4484124/security-update-for-sharepoint-foundation-2013-march-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4448f982");
  # https://support.microsoft.com/en-us/help/4475606/security-update-for-sharepoint-server-2013-march-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70c88fde");
  # https://support.microsoft.com/en-us/help/4475597/security-update-for-sharepoint-server-2010-march-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3028f961");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SharePoint Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0892");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-0850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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

bulletin = 'MS20-03';

kbs = make_list(
  '4484197', # 2010 SP2 Foundation
  '4475597', # 2010 SP2 Enterprise
  '4484282', # 2013 SP1 Foundation
  '4484124', # 2013 SP1 Foundation
  '4484150', # 2013 SP1 Enterprise
  '4475606', # 2013 SP1 Enterprise
  '4484272', # 2016 Enterprise
  '4484275', # 2016 Enterprise
  '4484271', # 2019 Core
  '4484277'  # 2019 Language Pack*
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
         'kb'          : '4484197',
         'path'        : hotfix_get_commonfilesdir(),
         'append'      : 'microsoft shared\\web server extensions\\14\\bin',
         'file'        : 'onetutil.dll',
         'version'     : '14.0.7246.5000',
         'product_name': 'Microsoft SharePoint Foundation Server 2010 SP 2'
      }],
    'Server':
      [{
         'kb'           : '4475597',
         'path'         : install['path'],
         'append'       : 'WebServices\\WordServer\\Core',
         'file'         : 'sword.dll',
         'version'      : '14.0.7246.5000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP 2'
      }]
    }
  },
  '2013':
  { '1':
    {'Foundation':
      [{
         'kb'           : '4484282',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\15\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '15.0.5223.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      },
      {
         'kb'           : '4484124',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\server15\\server setup controller',
         'file'         : 'wsssetup.dll',
         'version'      : '15.0.5223.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      }],
    'Server':
      [{
         'kb'           : '4484150',
         'path'         : install['path'],
         'append'       : 'transformapps',
         'file'         : 'docxpageconverter.exe',
         'version'      : '15.0.5223.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      },
      {
         'kb'           : '4475606',
         'path'         : install['path'],
         'append'       : 'WebServices\\ConversionServices',
         'file'         : 'sword.dll',
         'version'      : '15.0.5223.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      }]
    }
  },
  '2016':
  { '0':
    {'Server':
      [{
         'kb'           : '4484272',
         'path'         : install['path'],
         'append'       : 'WebServices\\ConversionServices',
         'file'         : 'sword.dll',
         'version'      : '16.0.4978.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
      },
      {
         'kb'           : '4484275',
         'path'         : install['path'],
         'append'       :'bin\\1033',
         'file'         : 'notessetup.exe',
         'version'      : '16.0.4585.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
      }]
    }
  },
  '2019':
  { '0':
    {'Server':
      [{
         'kb'           : '4484271',
         'path'         : install['path'],
         'append'       : 'WebServices\\ConversionServices',
         'file'         : 'sword.dll',
         'version'      : '16.0.10357.20002',
         'product_name' : 'Microsoft SharePoint Server 2019'
      },
      {
         'kb'           : '4484277',
         'path'         : install['path'],
         'append'       :'bin\\1033',
         'file'         : 'notessetup.exe',
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
reg_keys = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

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
    if (check['kb'] == '4484150' ||
        check['kb'] == '4484271' ||
        check['kb'] == '4484272' ||
        check['kb'] == '4484197' ||
        check['kb'] == '4484282'
    ) xss = TRUE;
  }
}

if (vuln)
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  if (xss) replace_kb_item(name:'www/' + port + '/XSS', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
