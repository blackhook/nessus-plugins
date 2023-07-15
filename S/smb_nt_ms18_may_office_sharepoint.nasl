#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(109616);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id(
    "CVE-2018-8149",
    "CVE-2018-8155",
    "CVE-2018-8156",
    "CVE-2018-8160",
    "CVE-2018-8161",
    "CVE-2018-8168"
  );
  script_xref(name:"MSKB", value:"4018388");
  script_xref(name:"MSKB", value:"4022135");
  script_xref(name:"MSKB", value:"4022130");
  script_xref(name:"MSKB", value:"4018381");
  script_xref(name:"MSKB", value:"3114889");
  script_xref(name:"MSKB", value:"4018390");
  script_xref(name:"MSKB", value:"4022145");
  script_xref(name:"MSKB", value:"4018398");
  script_xref(name:"MSFT", value:"MS18-4018388");
  script_xref(name:"MSFT", value:"MS18-4022135");
  script_xref(name:"MSFT", value:"MS18-4022130");
  script_xref(name:"MSFT", value:"MS18-4018381");
  script_xref(name:"MSFT", value:"MS18-3114889");
  script_xref(name:"MSFT", value:"MS18-4018390");
  script_xref(name:"MSFT", value:"MS18-4022145");
  script_xref(name:"MSFT", value:"MS18-4018398");
  script_xref(name:"IAVA", value:"2018-A-0151-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server and Microsoft Project Server (May 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server or Microsoft Project Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted web request to an affected SharePoint
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected SharePoint server. The attacker who
    successfully exploited the vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. These attacks could allow the attacker to read
    content that the attacker is not authorized to read, use
    the victim's identity to take actions on the SharePoint
    site on behalf of the user, such as change permissions
    and delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2018-8149,
    CVE-2018-8155, CVE-2018-8156, CVE-2018-8168)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8161)

  - An information disclosure vulnerability exists in
    Outlook when a message is opened. This vulnerability
    could potentially result in the disclosure of sensitive
    information to a malicious site.  (CVE-2018-8160)");
  # https://support.microsoft.com/en-us/help/4018388/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b7f20dd");
  # https://support.microsoft.com/en-us/help/4022135/description-of-the-security-update-for-sharepoint-server-2010-may-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1c9bcbe");
  # https://support.microsoft.com/en-us/help/4022130/description-of-the-security-update-for-project-server-2013-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88fa1a5e");
  # https://support.microsoft.com/en-us/help/4018381/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa122164");
  # https://support.microsoft.com/en-us/help/3114889/description-of-the-security-update-for-project-server-2010-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3a05613");
  # https://support.microsoft.com/en-us/help/4018390/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?861c0e32");
  # https://support.microsoft.com/en-us/help/4022145/description-of-the-security-update-for-sharepoint-server-2010-may-8-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66287670");
  # https://support.microsoft.com/en-us/help/4018398/description-of-the-security-update-for-sharepoint-foundation-2013-may
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f352ea51");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4018388
  -KB4022135
  -KB4022130
  -KB4018381
  -KB3114889
  -KB4018390
  -KB4022145
  -KB4018398");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_office_compatibility_pack_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::sharepoint::get_app_info();
var kb_checks = 
[
  {
    'product'      : '2010',
    'edition'      : 'Server',
    'kb'           : '3114889',
    'path'         :  app_info.path,
    'version'      : '14.0.7208.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Bin",
    'file'         : 'microsoft.office.project.server.pwa.dll',
    'product_name' : 'Microsoft Project Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'edition'      : 'Server',
    'kb'           : '4022135',
    'path'         :  app_info.path,
    'version'      : '14.0.7208.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2 (Word Automation Services)'
  },
  {
    'product'      : '2010',
    'edition'      : 'Server',
    'kb'           : '4022145',
    'path'         :  app_info.path,
    'version'      : '14.0.7209.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\14\ISAPI",
    'file'         : 'microsoft.sharepoint.portal.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4022130',
    'path'         :  app_info.path,
    'version'      : '15.0.5029.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Bin",
    'file'         : 'microsoft.office.project.server.pwa.dll',
    'product_name' : 'Microsoft Project Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4018388',
    'path'         :  app_info.path,
    'version'      : '15.0.5031.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1 (Word Automation Services)'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4018390',
    'path'         :  app_info.path,
    'version'      : '15.0.5027.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\ISAPI",
    'file'         : 'microsoft.sharepoint.portal.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4018398',
    'path'         :  app_info.path,
    'version'      : '15.0.5031.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Foundation 2013 SP1 (Word Automation Services)'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4018381',
    'path'         :  app_info.path,
    'version'      : '16.0.4690.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-05',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
