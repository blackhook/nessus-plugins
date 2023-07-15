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
  script_id(141436);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/08");

  script_cve_id(
    "CVE-2020-16941",
    "CVE-2020-16942",
    "CVE-2020-16944",
    "CVE-2020-16945",
    "CVE-2020-16946",
    "CVE-2020-16948",
    "CVE-2020-16951",
    "CVE-2020-16952",
    "CVE-2020-16953"
  );
  script_xref(name:"MSKB", value:"4486677");
  script_xref(name:"MSFT", value:"MS20-4486677");
  script_xref(name:"IAVA", value:"2020-A-0460-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2016 (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2016 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2016 installation on the
remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft SharePoint Server fails to properly handle
    objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the users system.  (CVE-2020-16948,
    CVE-2020-16953)

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
    application packages. (CVE-2020-16951, CVE-2020-16952)

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
    crafted URL.  (CVE-2020-16944)

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
    Server properly sanitizes web requests. (CVE-2020-16945,
    CVE-2020-16946)

  - An information disclosure vulnerability exists when
    Microsoft SharePoint Server improperly discloses its
    folder structure when rendering specific web pages. An
    attacker who took advantage of this information
    disclosure could view the folder path of scripts loaded
    on the page. To take advantage of the vulnerability, an
    attacker would require access to the specific SharePoint
    page affected by this vulnerability. The security update
    addresses the vulnerability by correcting how scripts
    are referenced on some SharePoint pages.
    (CVE-2020-16941, CVE-2020-16942)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4486677");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4486677 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16952");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft SharePoint Server-Side Include and ViewState RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

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

bulletin = 'MS20-10';

kbs = make_list(
  '4486677'
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
  '2016':
  { '0':
    {'Server':
      [{ 
         'kb'           : '4486677',
         'path'         : hotfix_get_commonfilesdir(),
         'append'       : 'microsoft shared\\web server extensions\\16\\bin',
         'file'         : 'onetutil.dll',
         'version'      : '16.0.5071.1000',
         'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
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
    if (check['kb'] == '4486677') xss = TRUE;
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


