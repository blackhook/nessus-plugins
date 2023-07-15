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
  script_id(136514);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id(
    "CVE-2020-1023",
    "CVE-2020-1024",
    "CVE-2020-1069",
    "CVE-2020-1099",
    "CVE-2020-1100",
    "CVE-2020-1101",
    "CVE-2020-1102",
    "CVE-2020-1103",
    "CVE-2020-1104",
    "CVE-2020-1105",
    "CVE-2020-1106",
    "CVE-2020-1107"
  );
  script_xref(name:"MSKB", value:"4484336");
  script_xref(name:"MSKB", value:"4484364");
  script_xref(name:"MSKB", value:"4484383");
  script_xref(name:"MSKB", value:"4484352");
  script_xref(name:"MSKB", value:"4484332");
  script_xref(name:"MSFT", value:"MS20-4484336");
  script_xref(name:"MSFT", value:"MS20-4484364");
  script_xref(name:"MSFT", value:"MS20-4484383");
  script_xref(name:"MSFT", value:"MS20-4484352");
  script_xref(name:"MSFT", value:"MS20-4484332");
  script_xref(name:"IAVA", value:"2020-A-0215-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server (May 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

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
    Server properly sanitizes web requests. (CVE-2020-1099,
    CVE-2020-1100, CVE-2020-1101, CVE-2020-1106)

  - An information disclosure vulnerability exists where
    certain modes of the search function in Microsoft
    SharePoint Server are vulnerable to cross-site search
    attacks (a variant of cross-site request forgery, CSRF).
    When users are simultaneously logged in to Microsoft
    SharePoint Server and visit a malicious web page, the
    attacker can, through standard browser functionality,
    induce the browser to invoke search queries as the
    logged in user. While the attacker cant access the
    search results or documents as such, the attacker can
    determine whether the query did return results or not,
    and thus by issuing targeted queries discover facts
    about documents that are searchable for the logged-in
    user. The security update addresses the vulnerability by
    running the search queries in a way that doesnt expose
    them to this browser vulnerability. (CVE-2020-1103)

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
    application packages. (CVE-2020-1023, CVE-2020-1024,
    CVE-2020-1102)

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
    Server properly sanitizes web requests. (CVE-2020-1104,
    CVE-2020-1105, CVE-2020-1107)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint Server when it fails to properly
    identify and filter unsafe ASP.Net web controls. An
    authenticated attacker who successfully exploited the
    vulnerability could use a specially crafted page to
    perform actions in the security context of the
    SharePoint application pool process.  (CVE-2020-1069)");
  # https://support.microsoft.com/en-us/help/4484336/security-update-for-sharepoint-server-2016-may-12-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16c795ce");
  # https://support.microsoft.com/en-us/help/4484364/security-update-for-sharepoint-foundation-2013-may
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fc997cf");
  # https://support.microsoft.com/en-us/help/4484383/security-update-for-sharepoint-server-2010-may-12-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?753e4507");
  # https://support.microsoft.com/en-us/help/4484352/security-update-for-sharepoint-enterprise-server-2013-may-12-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9389843a");
  # https://support.microsoft.com/en-us/help/4484332/security-update-for-sharepoint-server-2019-may-12-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?381e7ad4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484336
  -KB4484332
  -KB4484352
  -KB4484364
  -KB4484383");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1102");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS20-05';

kbs = make_list(
  '4484336',
  '4484332',
  '4484352',
  '4484364',
  '4484383'
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
    {'Server':
      [{
         'kb'          : '4484383',
         'path'        : install['path'],
         'append'      : 'bin',
         'file'        : 'microsoft.sharepoint.publishing.dll',
         'version'     : '14.0.7249.5000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP 2'
      }]
    }
  },
  '2013':
  { '1':
    {'Foundation':
      [{
         'kb'           : '4484364',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\15\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '15.0.5241.1000',
         'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
      }],
    'Server':
      [{
         'kb'           : '4484352',
         'path'         : install['path'],
         'append'       : 'transformapps',
         'file'         : 'docxpageconverter.exe',
         'version'      : '15.0.5241.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
      }]
    }
  },
  '2016':
  { '0':
    {'Server':
      [{ 
         'kb'           : '4484336',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'microsoft.sharepoint.publishing.dll',
         'version'      : '16.0.5005.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
      }]
    }
  },
  '2019':
  { '0':
    {'Server':
      [      {
         'kb'           : '4484332',
         'path'         : install['path'],
         'append'       :'bin',
         'file'         : 'ascalc.dll',
         'version'      : '16.0.10359.20000',
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
    if (check['kb'] == '4484383' ||
        check['kb'] == '4484332' ||
        check['kb'] == '4484336' ||
        check['kb'] == '4484364' ||
        check['kb'] == '4484352'
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
