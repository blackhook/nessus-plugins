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
  script_id(138512);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-1025",
    "CVE-2020-1147",
    "CVE-2020-1342",
    "CVE-2020-1439",
    "CVE-2020-1443",
    "CVE-2020-1444",
    "CVE-2020-1445",
    "CVE-2020-1446",
    "CVE-2020-1447",
    "CVE-2020-1448",
    "CVE-2020-1450",
    "CVE-2020-1451",
    "CVE-2020-1454",
    "CVE-2020-1456"
  );
  script_xref(name:"MSKB", value:"4484443");
  script_xref(name:"MSKB", value:"4484451");
  script_xref(name:"MSKB", value:"4484411");
  script_xref(name:"MSKB", value:"4484374");
  script_xref(name:"MSKB", value:"4484436");
  script_xref(name:"MSKB", value:"4484452");
  script_xref(name:"MSKB", value:"4484453");
  script_xref(name:"MSKB", value:"4484440");
  script_xref(name:"MSKB", value:"4484348");
  script_xref(name:"MSKB", value:"4484370");
  script_xref(name:"MSKB", value:"4484448");
  script_xref(name:"MSKB", value:"4484353");
  script_xref(name:"MSKB", value:"4484460");
  script_xref(name:"MSFT", value:"MS20-4484443");
  script_xref(name:"MSFT", value:"MS20-4484451");
  script_xref(name:"MSFT", value:"MS20-4484411");
  script_xref(name:"MSFT", value:"MS20-4484374");
  script_xref(name:"MSFT", value:"MS20-4484436");
  script_xref(name:"MSFT", value:"MS20-4484452");
  script_xref(name:"MSFT", value:"MS20-4484453");
  script_xref(name:"MSFT", value:"MS20-4484440");
  script_xref(name:"MSFT", value:"MS20-4484348");
  script_xref(name:"MSFT", value:"MS20-4484370");
  script_xref(name:"MSFT", value:"MS20-4484448");
  script_xref(name:"MSFT", value:"MS20-4484353");
  script_xref(name:"MSFT", value:"MS20-4484460");
  script_xref(name:"IAVA", value:"2020-A-0311-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft SharePoint Server (July 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server and Skype for Business
    Server improperly handle OAuth token validation. An
    attacker who successfully exploited the vulnerability
    could bypass authentication and achieve improper access.
    (CVE-2020-1025)

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2020-1445)

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2020-1342)

  - A remote code execution vulnerability exists in
    PerformancePoint Services for SharePoint Server when the
    software fails to check the source markup of XML file
    input. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the process responsible for deserialization of the XML
    content.  (CVE-2020-1439)

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
    Server properly sanitizes web requests. (CVE-2020-1450,
    CVE-2020-1451, CVE-2020-1456)

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
    Server properly sanitizes web requests. (CVE-2020-1443)

  - A remote code execution vulnerability exists in the way
    Microsoft SharePoint software parses specially crafted
    email messages. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the system user. An attacker could then
    install programs; view, change, add, or delete data.
    (CVE-2020-1444)

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
    crafted URL to the user of the targeted SharePoint Web
    App site and convincing the user to click the specially
    crafted URL.  (CVE-2020-1454)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-1446,
    CVE-2020-1447, CVE-2020-1448)

  - A remote code execution vulnerability exists in .NET
    Framework, Microsoft SharePoint, and Visual Studio when
    the software fails to check the source markup of XML
    file input. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the process responsible for deserialization of the XML
    content.  (CVE-2020-1147)");
  # https://support.microsoft.com/en-us/help/4484443/security-update-for-sharepoint-server-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1100364");
  # https://support.microsoft.com/en-us/help/4484451/security-update-for-office-online-server-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cce850ff");
  # https://support.microsoft.com/en-us/help/4484411/security-update-for-sharepoint-foundation-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18413cb3");
  # https://support.microsoft.com/en-us/help/4484374/security-update-for-sharepoint-server-2010-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cc0694a");
  # https://support.microsoft.com/en-us/help/4484436/security-update-for-sharepoint-server-2016-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3072fa83");
  # https://support.microsoft.com/en-us/help/4484452/security-update-for-sharepoint-server-2019-language-pack-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1863e77");
  # https://support.microsoft.com/en-us/help/4484453/security-update-for-sharepoint-server-2019-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a7e0254");
  # https://support.microsoft.com/en-us/help/4484440/security-update-for-sharepoint-server-2016-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c979319");
  # https://support.microsoft.com/en-us/help/4484348/security-update-for-sharepoint-server-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04aa536f");
  # https://support.microsoft.com/en-us/help/4484370/security-update-for-sharepoint-server-2010-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?270b620b");
  # https://support.microsoft.com/en-us/help/4484448/security-update-for-sharepoint-foundation-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e00ca47");
  # https://support.microsoft.com/en-us/help/4484353/security-update-for-sharepoint-server-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ae8e571");
  # https://support.microsoft.com/en-us/help/4484460/security-update-for-sharepoint-server-2010-july-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?331c84f8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SharePoint Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1025");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SharePoint DataSet / DataTable Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/15");

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

bulletin = 'MS20-07';

kbs = make_list(
  '4484374', # 2010 Server 
  '4484460', # 2010 Server
  '4484370', # 2010 Server
  '4484448', # 2013 Foundation
  '4484411', # 2013 Foundation
  '4484443', # 2013 Enterprise
  '4484353', # 2013 Enterprise
  '4484348', # 2013 Enterprise
  '4484436', # 2016 Enterprise
  '4484440', # 2016 Enterprise
  '4484452', # 2019 Language pack
  '4484453'  # 2019 Server
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
    {'Server':
      [{
         'kb'           : '4484374',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\14\\template\\layouts\\ppsma\\1033\\designerinstall',
         'file'         : 'Microsoft.PerformancePoint.Scorecards.Client.dll.deploy',
         'version'      : '14.0.7254.5000',
         'product_name' : 'Microsoft SharePoint Server 2010 SP 2'
      },
      {
         'kb'           : '4484460',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'microsoft.office.server.chart.dll',
         'version'      : '14.0.7254.5000',
         'product_name' : 'Microsoft SharePoint Server 2010 SP 2'
      },
      {
         'kb'           : '4484370',
         'path'         : install['path'],
         'append'       : 'webservices\\wordserver\\core',
         'file'         : 'sword.dll',
         'version'      : '14.0.7254.5000',
         'product_name' : 'Microsoft SharePoint Server 2010 SP 2'
      }]
    }
  },
  '2013':
  { '1':
    {'Foundation':
      [{
         'kb'           : '4484448',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\15\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '15.0.5259.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      },
      {
         'kb'           : '4484411',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\server15\\server setup controller',
         'file'         : 'wsssetup.dll',
         'version'      : '15.0.5259.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      }],
    'Server':
      [{ 
         'kb'           : '4484443',
         'path'         : install['path'],
         'append'       : 'webservices\\conversionservices',
         'file'         : 'msoserver.dll',
         'version'      : '15.0.5249.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      },
      { 
         'kb'           : '4484353',
         'path'         : install['path'],
         'append'       : 'webservices\\conversionservices',
         'file'         : 'htmlutil.dll',
         'version'      : '15.0.5249.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      },
      { 
         'kb'           : '4484348',
         'path'         : install['path'],
         'append'       : 'webservices\\conversionservices',
         'file'         : 'sword.dll',
         'version'      : '15.0.5259.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      }
      ]
    }
  },
  '2016':
  { '0':
    {'Server':
      [{ 
         'kb'           : '4484436',
         'path'         : install['path'],
         'append'       : 'transformapps',
         'file'         : 'docxpageconverter.exe',
         'version'      : '16.0.5023.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
      },
      { 
         'kb'           : '4484440',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\server16\\server setup controller',
         'file'         : 'wsssetup.dll',
         'version'      : '16.0.5023.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
      }
      ]
    }
  },
  '2019':
  { '0':
    {'Server':
     [{
         'kb'           : '4484452',
         'path'         : install['path'],
         'append'       : 'bin\\1033',
         'file'         : 'notessetup.exe',
         'version'      : '16.0.10362.20025',
         'product_name' : 'Microsoft SharePoint Server 2019'
      },
      {
         'kb'           : '4484453',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\16\\bin',
         'file'         : 'csisrv.dll',
         'version'      : '16.0.10363.12107',
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

  if(check['kb'] == '4484452')
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
  }
  
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
    if (check['kb'] == '4484452' ||
        check['kb'] == '4484453' ||
        check['kb'] == '4484443' ||
        check['kb'] == '4484460' ||
        check['kb'] == '4484460' ||
        check['kb'] == '4484436' 
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

