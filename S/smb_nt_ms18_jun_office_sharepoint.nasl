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
  script_id(110497);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2018-8252", "CVE-2018-8254");
  script_xref(name:"MSKB", value:"4022179");
  script_xref(name:"MSKB", value:"4022173");
  script_xref(name:"MSKB", value:"4022210");
  script_xref(name:"MSKB", value:"4018391");
  script_xref(name:"MSKB", value:"4022190");
  script_xref(name:"MSKB", value:"4022197");
  script_xref(name:"MSFT", value:"MS18-4022179");
  script_xref(name:"MSFT", value:"MS18-4022173");
  script_xref(name:"MSFT", value:"MS18-4022210");
  script_xref(name:"MSFT", value:"MS18-4018391");
  script_xref(name:"MSFT", value:"MS18-4022190");
  script_xref(name:"MSFT", value:"MS18-4022197");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (June 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

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
    Server properly sanitizes web requests. (CVE-2018-8252,
    CVE-2018-8254)");
  # https://support.microsoft.com/en-us/help/4022179/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d55fcf27");
  # https://support.microsoft.com/en-us/help/4022173/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbe95a40");
  # https://support.microsoft.com/en-us/help/4022210/description-of-the-security-update-for-project-server-2010-june-12-201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7ab8557");
  # https://support.microsoft.com/en-us/help/4018391/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a24384e1");
  # https://support.microsoft.com/en-us/help/4022190/description-of-the-security-update-for-sharepoint-foundation-2013-june
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a73b0a8");
  # https://support.microsoft.com/en-us/help/4022197/description-of-the-security-update-for-sharepoint-server-2010-june
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d0d1103");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4022179
  -KB4022173
  -KB4022210
  -KB4018391
  -KB4022190
  -KB4022197");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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
    'kb'           : '4022210',
    'path'         :  app_info.path,
    'version'      : '14.0.7210.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Bin",
    'file'         : 'microsoft.office.project.server.pwa.dll',
    'product_name' : 'Microsoft Project Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'edition'      : 'Server',
    'kb'           : '4022197',
    'path'         :  app_info.path,
    'version'      : '14.0.7210.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'oartserver.dll',
    'product_name' : 'SharePoint Server 2010 SP2 (Word Automation Services)'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4022179',
    'path'         :  app_info.path,
    'version'      : '15.0.5041.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'SharePoint Enterprise Server 2013 SP1 (Word Automation Services)'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4018391',
    'path'         :  app_info.path,
    'version'      : '15.0.5041.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'SharePoint Enterprise Server 2013 SP1 (Excel Services)'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4022190',
    'path'         :  app_info.path,
    'version'      : '15.0.5041.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft SharePoint Foundation 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4022173',
    'path'         :  app_info.path,
    'version'      : '16.0.4705.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-06',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
