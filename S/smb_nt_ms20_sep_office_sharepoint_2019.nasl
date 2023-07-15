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
  script_id(140521);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-1198",
    "CVE-2020-1200",
    "CVE-2020-1205",
    "CVE-2020-1210",
    "CVE-2020-1218",
    "CVE-2020-1227",
    "CVE-2020-1335",
    "CVE-2020-1338",
    "CVE-2020-1345",
    "CVE-2020-1440",
    "CVE-2020-1452",
    "CVE-2020-1453",
    "CVE-2020-1460",
    "CVE-2020-1482",
    "CVE-2020-1514",
    "CVE-2020-1523",
    "CVE-2020-1576",
    "CVE-2020-1595"
  );
  script_xref(name:"MSFT", value:"MS20-4484504");
  script_xref(name:"MSFT", value:"MS20-4484505");
  script_xref(name:"MSKB", value:"4484504");
  script_xref(name:"MSKB", value:"4484505");
  script_xref(name:"IAVA", value:"2020-A-0412-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2019 (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

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
    application packages. (CVE-2020-1200, CVE-2020-1210,
    CVE-2020-1452, CVE-2020-1453, CVE-2020-1576)

  - A tampering vulnerability exists when Microsoft
    SharePoint Server fails to properly handle profile data.
    An attacker who successfully exploited this
    vulnerability could modify a targeted user's profile
    data.  (CVE-2020-1440, CVE-2020-1523)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint where APIs aren't properly
    protected from unsafe data input. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the SharePoint
    application pool and the SharePoint server farm account.
    Exploitation of this vulnerability requires that a user
    access a susceptible API on an affected version of
    SharePoint with specially-formatted input. The security
    update addresses the vulnerability by correcting how
    SharePoint handles deserialization of untrusted data.
    (CVE-2020-1595)

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
    Server properly sanitizes web requests. (CVE-2020-1205)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint Server when it fails to properly
    identify and filter unsafe ASP.Net web controls. An
    authenticated attacker who successfully exploited the
    vulnerability could use a specially crafted page to
    perform actions in the security context of the
    SharePoint application pool process.  (CVE-2020-1460)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-1218,
    CVE-2020-1338)

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
    Server properly sanitizes web requests. (CVE-2020-1198,
    CVE-2020-1227, CVE-2020-1345, CVE-2020-1482,
    CVE-2020-1514)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2020-1335)");
  # https://support.microsoft.com/en-us/help/4484504/security-update-for-sharepoint-server-2019-language-pack-sept-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?487dc0dc");
  # https://support.microsoft.com/en-us/help/4484505/security-update-for-sharepoint-server-2019-sept-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0917a96e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SharePoint Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1453");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1595");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
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

bulletin = 'MS20-09';

kbs = make_list(
    '4484504',
    '4484505'
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
  '2019':
  { '0':
    {'Server':
     [{
         'kb'           : '4484504',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'microsoft.sharepoint.publishing.dll',
         'version'      : '16.0.10366.12106',
         'product_name' : 'Microsoft SharePoint Server 2019'
      },
      {
         'kb'           : '4484505',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'ascalc.dll',
         'version'      : '16.0.10366.12106',
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
    if (check['kb'] == '4484504' || check['kb'] == '4484505') xss = TRUE;
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


