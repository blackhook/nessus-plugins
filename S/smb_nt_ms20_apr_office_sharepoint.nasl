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
  script_id(135675);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/08");

  script_cve_id(
    "CVE-2020-0920",
    "CVE-2020-0923",
    "CVE-2020-0924",
    "CVE-2020-0925",
    "CVE-2020-0926",
    "CVE-2020-0927",
    "CVE-2020-0929",
    "CVE-2020-0930",
    "CVE-2020-0931",
    "CVE-2020-0932",
    "CVE-2020-0933",
    "CVE-2020-0954",
    "CVE-2020-0971",
    "CVE-2020-0972",
    "CVE-2020-0973",
    "CVE-2020-0974",
    "CVE-2020-0975",
    "CVE-2020-0976",
    "CVE-2020-0977",
    "CVE-2020-0978",
    "CVE-2020-0980"
  );
  script_xref(name:"MSKB", value:"4011581");
  script_xref(name:"MSKB", value:"4011584");
  script_xref(name:"MSKB", value:"4484291");
  script_xref(name:"MSKB", value:"4484292");
  script_xref(name:"MSKB", value:"4484293");
  script_xref(name:"MSKB", value:"4484297");
  script_xref(name:"MSKB", value:"4484298");
  script_xref(name:"MSKB", value:"4484299");
  script_xref(name:"MSKB", value:"4484301");
  script_xref(name:"MSKB", value:"4484307");
  script_xref(name:"MSKB", value:"4484308");
  script_xref(name:"MSKB", value:"4484321");
  script_xref(name:"MSKB", value:"4484322");
  script_xref(name:"MSFT", value:"MS20-4011581");
  script_xref(name:"MSFT", value:"MS20-4011584");
  script_xref(name:"MSFT", value:"MS20-4484291");
  script_xref(name:"MSFT", value:"MS20-4484292");
  script_xref(name:"MSFT", value:"MS20-4484293");
  script_xref(name:"MSFT", value:"MS20-4484297");
  script_xref(name:"MSFT", value:"MS20-4484298");
  script_xref(name:"MSFT", value:"MS20-4484299");
  script_xref(name:"MSFT", value:"MS20-4484301");
  script_xref(name:"MSFT", value:"MS20-4484307");
  script_xref(name:"MSFT", value:"MS20-4484308");
  script_xref(name:"MSFT", value:"MS20-4484321");
  script_xref(name:"MSFT", value:"MS20-4484322");
  script_xref(name:"IAVA", value:"2020-A-0155-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server (April 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-0980)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint when the software fails to check
    the source markup of an application package. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the SharePoint
    application pool and the SharePoint server farm account.
    Exploitation of this vulnerability requires that a user
    uploads a specially crafted SharePoint application
    package to an affected version of SharePoint. The
    security update addresses the vulnerability by
    correcting how SharePoint checks the source markup of
    application packages. (CVE-2020-0920, CVE-2020-0929,
    CVE-2020-0931, CVE-2020-0932, CVE-2020-0971,
    CVE-2020-0974)

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
    Server properly sanitizes web requests. (CVE-2020-0923,
    CVE-2020-0924, CVE-2020-0925, CVE-2020-0926,
    CVE-2020-0927, CVE-2020-0930, CVE-2020-0933,
    CVE-2020-0954, CVE-2020-0973, CVE-2020-0978)

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
    Server properly sanitizes web requests. (CVE-2020-0972,
    CVE-2020-0975, CVE-2020-0976, CVE-2020-0977)");
  # https://support.microsoft.com/en-us/help/4484301/security-update-for-sharepoint-server-2016-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14098d8a");
  # https://support.microsoft.com/en-us/help/4484298/security-update-for-sharepoint-foundation-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0634cc8e");
  # https://support.microsoft.com/en-us/help/4484299/security-update-for-sharepoint-server-2016-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b226f5e7");
  # https://support.microsoft.com/en-us/help/4484322/security-update-for-sharepoint-foundation-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f210025f");
  # https://support.microsoft.com/en-us/help/4484297/security-update-for-sharepoint-server-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6bffe1f");
  # https://support.microsoft.com/en-us/help/4484321/security-update-for-sharepoint-foundation-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?301f9037");
  # https://support.microsoft.com/en-us/help/4484292/security-update-for-sharepoint-server-2019-april-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?948ef665");
  # https://support.microsoft.com/en-us/help/4484293/security-update-for-sharepoint-server-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?146e79ea");
  # https://support.microsoft.com/en-us/help/4484307/security-update-for-sharepoint-server-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f656ea7");
  # https://support.microsoft.com/en-us/help/4484291/security-update-for-sharepoint-server-2019-language-pack
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b112be9");
  # https://support.microsoft.com/en-us/help/4484308/security-update-for-sharepoint-server-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705dbbc1");
  # https://support.microsoft.com/en-us/help/4011581/security-update-for-sharepoint-foundation-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c81717de");
  # https://support.microsoft.com/en-us/help/4011584/security-update-for-sharepoint-server-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c86af69");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SharePoint Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0980");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-0974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS20-04';

kbs = make_list(
  '4484298', # 2010 SP2 Foundation 
  '4484293', # 2010 SP2 Enterprise 
  '4011581', # 2013 SP1 Foundation 
  '4484321', # 2013 SP1 Foundation 
  '4484322', # 2013 SP1 Foundation
  '4011584', # 2013 SP1 Enterprise
  '4484307', # 2013 SP1 Enterprise
  '4484308', # 2013 SP1 Enterprise
  '4484299', # 2016 Enterprise
  '4484301', # 2016 Enterprise
  '4484291', # 2019 Language Pack*
  '4484292'  # 2019 Core
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
         'kb'          : '4484298',
         'path'        : hotfix_get_commonfilesdir(),
         'append'      : 'microsoft shared\\web server extensions\\14\\bin',
         'file'        : 'csisrv.dll',
         'version'     : '14.0.7248.5000',
         'product_name': 'Microsoft SharePoint Foundation Server 2010 SP 2'
      }],
    'Server':
      [{
         'kb'           : '4484293',
         'path'         : install['path'],
         'append'       :'webservices\\wordserver\\core',
         'file'         : 'msoserver.dll',
         'version'      : '14.0.7248.5000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP 2'
      }]
    }
  },
  '2013':
  { '1':
    {'Foundation':
      [{
         'kb'           : '4011581',
         'path'         : install['path'],
         'append'       :'webservices\\conversionservices',
         'file'         : 'msoserver.dll',
         'version'      : '15.0.5233.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      },
      {
         'kb'           : '4484321',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\15\\bin',
         'file'         : 'csisrv.dll',
         'version'      : '15.0.5233.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      },
      {
         'kb'           : '4484322',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\server15\\server setup controller',
         'file'         : 'wsssetup.dll',
         'version'      : '15.0.5233.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      }],
    'Server':
      [{
         'kb'           : '4011584',
         'path'         : install['path'],
         'append'       : 'transformapps',
         'file'         : 'msoserver.dll',
         'version'      : '15.0.5233.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      },
      {
         'kb'           : '4484307',
         'path'         : install['path'],
         'append'       : 'webservices\\conversionservices',
         'file'         : 'sword.dll',
         'version'      : '15.0.5233.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      },
      { 
         'kb'           : '4484308',
         'path'         : install['path'],
         'append'       : 'transformapps',
         'file'         : 'docxpageconverter.exe',
         'version'      : '15.0.5233.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      }]
    }
  },
  '2016':
  { '0':
    {'Server':
      [{ 
         'kb'           : '4484299',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'microsoft.sharepoint.publishing.dll',
         'version'      : '16.0.4993.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
      },
      {
         'kb'           : '4484301',
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
      [      {
         'kb'           : '4484291',
         'path'         : install['path'],
         'append'       :'bin\\1033',
         'file'         : 'notessetup.exe',
         'version'      : '16.0.10358.20000',
         'product_name' : 'Microsoft SharePoint Server 2019'
      },
      {
         'kb'           : '4484292',
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
    if (check['kb'] == '4484298' ||
        check['kb'] == '4011581' ||
        check['kb'] == '4484321' ||
        check['kb'] == '4484322' ||
        check['kb'] == '4484308' ||
        check['kb'] == '4484299' ||
        check['kb'] == '4484301' ||
        check['kb'] == '4484291' ||
        check['kb'] == '4484292'
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
