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
  script_id(121044);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2019-0556",
    "CVE-2019-0557",
    "CVE-2019-0558",
    "CVE-2019-0561",
    "CVE-2019-0562",
    "CVE-2019-0585"
  );
  script_xref(name:"MSKB", value:"4461589");
  script_xref(name:"MSKB", value:"4461591");
  script_xref(name:"MSKB", value:"4461596");
  script_xref(name:"MSKB", value:"4461598");
  script_xref(name:"MSKB", value:"4461612");
  script_xref(name:"MSKB", value:"4461624");
  script_xref(name:"MSFT", value:"MS19-4461589");
  script_xref(name:"MSFT", value:"MS19-4461591");
  script_xref(name:"MSFT", value:"MS19-4461596");
  script_xref(name:"MSFT", value:"MS19-4461598");
  script_xref(name:"MSFT", value:"MS19-4461612");
  script_xref(name:"MSFT", value:"MS19-4461624");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-0585)

  - An information disclosure vulnerability exists when
    Microsoft Word macro buttons are used improperly. An
    attacker who successfully exploited this vulnerability
    could read arbitrary files from a targeted system.
    (CVE-2019-0561)

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
    Server properly sanitizes web requests. (CVE-2019-0556,
    CVE-2019-0557, CVE-2019-0558)

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
    Server properly sanitizes web requests. (CVE-2019-0562)");
  # https://support.microsoft.com/en-us/help/4461598/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6d2ab16");
  # https://support.microsoft.com/en-us/help/4461589/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e29ca806");
  # https://support.microsoft.com/en-us/help/4461624/description-of-the-security-update-for-sharepoint-server-2010-january
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d381f3b5");
  # https://support.microsoft.com/en-us/help/4461591/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ecf450e");
  # https://support.microsoft.com/en-us/help/4461596/description-of-the-security-update-for-sharepoint-foundation-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c5e0eeb");
  # https://support.microsoft.com/en-us/help/4461612/description-of-the-security-update-for-sharepoint-server-2010-january
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22a7bc27");
  # https://support.microsoft.com/en-us/help/4461634/description-of-the-security-update-for-sharepoint-server-2019-january
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e1b9657");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461589
  -KB4461591
  -KB4461596
  -KB4461598
  -KB4461612
  -KB4461624
  -KB4461634");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'kb'           : '4461612',
    'path'         :  app_info.path,
    'version'      : '14.0.7228.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4461589',
    'path'         :  app_info.path,
    'version'      : '15.0.5101.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4461591',
    'path'         :  app_info.path,
    'version'      : '15.0.5101.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "TransformApps",
    'file'         : 'docxpageconverter.exe',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4461596',
    'path'         :  app_info.path,
    'version'      : '15.0.5101.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\15\bin",
    'file'         : 'csisrv.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4461598',
    'path'         :  app_info.path,
    'version'      : '16.0.4795.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "BIN",
    'file'         : 'ascalc.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4461634',
    'path'         :  app_info.path,
    'version'      : '16.0.10340.12101',
    'min_version'  : '16.0.0.0',
    'append'       : "BIN",
    'file'         : 'ascalc.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-01',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
