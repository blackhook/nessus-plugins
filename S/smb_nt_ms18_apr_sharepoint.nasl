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
  script_id(109036);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2018-1005",
    "CVE-2018-1014",
    "CVE-2018-1028",
    "CVE-2018-1032",
    "CVE-2018-1034"
  );
  script_xref(name:"MSKB", value:"4018336");
  script_xref(name:"MSKB", value:"4018342");
  script_xref(name:"MSKB", value:"4018343");
  script_xref(name:"MSKB", value:"4018341");
  script_xref(name:"MSKB", value:"4018356");
  script_xref(name:"MSKB", value:"4011586");
  script_xref(name:"MSKB", value:"4011712");
  script_xref(name:"MSFT", value:"MS18-4018336");
  script_xref(name:"MSFT", value:"MS18-4018342");
  script_xref(name:"MSFT", value:"MS18-4018343");
  script_xref(name:"MSFT", value:"MS18-4018341");
  script_xref(name:"MSFT", value:"MS18-4018356");
  script_xref(name:"MSFT", value:"MS18-4011586");
  script_xref(name:"MSFT", value:"MS18-4011712");

  script_name(english:"Security Updates for Microsoft SharePoint Server (April 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the
remote host is missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize
    a specially crafted web request to an affected
    SharePoint server. An authenticated attacker could
    exploit the vulnerability by sending a specially
    crafted request to an affected SharePoint server.
    (CVE-2018-1005)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize
    a specially crafted web request to an affected
    SharePoint server. An authenticated attacker could
    exploit the vulnerability by sending a specially
    crafted URL to a user of an affected SharePoint
    server. (CVE-2018-1014)

  - A remote code execution vulnerability exists when the
    Office graphics component improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system
    could be less impacted than users who operate with
    administrative user rights. (CVE-2018-1028)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize
    a specially crafted web request to an affected
    SharePoint server. An authenticated attacker could
    exploit the vulnerability by sending a specially
    crafted request to an affected SharePoint server.
    (CVE-2018-1032)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize
    a specially crafted web request to an affected
    SharePoint server. An authenticated attacker could
    exploit the vulnerability by sending a specially
    crafted request to an affected SharePoint server.
    (CVE-2018-1034)");
  # https://support.microsoft.com/en-us/help/4018336/description-of-the-security-update-for-sps-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c77ed1e3");
  # https://support.microsoft.com/en-us/help/4018342/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65f69ee4");
  # https://support.microsoft.com/en-us/help/4018343/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a01e2a2f");
  # https://support.microsoft.com/en-us/help/4018341/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cc634b1");
  # https://support.microsoft.com/en-us/help/4018356/description-of-the-security-update-for-word-automation-services-on
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e6b2ff8");
  # https://support.microsoft.com/en-us/help/4011586/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6e46081");
  # https://support.microsoft.com/en-us/help/4011712/description-of-the-security-update-for-sharepoint-server-2010-april-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?400dbbb7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue: 
  -KB4018336
  -KB4018342
  -KB4018343
  -KB4018341
  -KB4018356
  -KB4011586
  -KB4011712");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1028");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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

dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'app_info ' + '\nTYPE OF : ' + typeof(app_info) + '\n' + obj_rep(app_info) + '\n\n'); ###### REMOVE AFTER DEBUGGING ######



var kb_checks = 
[
  {
    'product'      : '2010',
    'kb'           : '4018356',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '14.0.7197.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'kb'           : '4011712',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '14.0.7192.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\14\ISAPI",
    'file'         : 'microsoft.sharepoint.portal.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'kb'           : '4011586',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5023.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices\1033",
    'file'         : 'ppintl.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4018341',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5023.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices\1033",
    'file'         : 'wwintl.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4018342',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5021.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\ISAPI",
    'file'         : 'microsoft.office.server.search.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4018343',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.4745.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\ISAPI",
    'file'         : 'microsoft.sharepoint.client.userprofiles.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'kb'           : '4018336',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '16.0.4678.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-04',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
