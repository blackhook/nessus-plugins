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
  script_id(128767);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2019-1257",
    "CVE-2019-1259",
    "CVE-2019-1260",
    "CVE-2019-1261",
    "CVE-2019-1262",
    "CVE-2019-1295",
    "CVE-2019-1296"
  );
  script_bugtraq_id(108619, 109364);
  script_xref(name:"MSKB", value:"4475605");
  script_xref(name:"MSKB", value:"4475596");
  script_xref(name:"MSKB", value:"4484098");
  script_xref(name:"MSKB", value:"4484099");
  script_xref(name:"MSKB", value:"4475590");
  script_xref(name:"MSKB", value:"4475594");
  script_xref(name:"MSKB", value:"4464557");
  script_xref(name:"MSFT", value:"MS19-4475605");
  script_xref(name:"MSFT", value:"MS19-4475596");
  script_xref(name:"MSFT", value:"MS19-4484098");
  script_xref(name:"MSFT", value:"MS19-4484099");
  script_xref(name:"MSFT", value:"MS19-4475590");
  script_xref(name:"MSFT", value:"MS19-4475594");
  script_xref(name:"MSFT", value:"MS19-4464557");

  script_name(english:"Security Updates for Microsoft SharePoint Server (September 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in
    Microsoft SharePoint. An attacker who successfully
    exploited this vulnerability could attempt to
    impersonate another user of the SharePoint server.
    (CVE-2019-1260)

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
    Server properly sanitizes web requests. (CVE-2019-1262)

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
    (CVE-2019-1295, CVE-2019-1296)

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
    application packages. (CVE-2019-1257)

  - A spoofing vulnerability exists in Microsoft SharePoint
    when it improperly handles requests to authorize
    applications, resulting in cross-site request forgery
    (CSRF).  (CVE-2019-1259, CVE-2019-1261)");
  # https://support.microsoft.com/en-us/help/4475605/security-update-for-sharepoint-foundation-2010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c085bce");
  # https://support.microsoft.com/en-us/help/4484098/security-update-for-sharepoint-foundation-2013-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ddc5ed7");
  # https://support.microsoft.com/en-us/help/4484099/security-update-for-sharepoint-foundation-2013-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c06995e");
  # https://support.microsoft.com/en-us/help/4475590/security-update-for-sharepoint-enterprise-server-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15708b9a");
  # https://support.microsoft.com/en-us/help/4475594/security-update-for-sharepoint-server-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?097ca066");
  # https://support.microsoft.com/en-us/help/4475596/security-update-for-sharepoint-server-2019-september-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?319bb185");
  # https://support.microsoft.com/en-us/help/4464557/security-update-for-sharepoint-server-2019-language-pack
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7d7f4dd");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4475605
  -KB4475596
  -KB4484098
  -KB4484099
  -KB4475590
  -KB4475594
  -KB4464557");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1261");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1296");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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
    'edition'      : 'Foundation',
    'kb'           : '4475605',
    'path'         :  app_info.path,
    'version'      : '14.0.7237.5000',
    'append'       : "microsoft shared\web server extensions\14\bin",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4484098',
    'path'         :  app_info.path,
    'version'      : '15.0.5172.1000',
    'append'       : "microsoft shared\web server extensions\15\bin",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4484099',
    'path'         :  app_info.path,
    'version'      : '15.0.4508.1000',
    'append'       : "microsoft shared\dw\1033",
    'file'         : 'dwintl20.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4475590',
    'path'         :  app_info.path,
    'version'      : '16.0.4900.1000',
    'append'       : "transformapps",
    'file'         : 'docxpageconverter.exe',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4475594',
    'path'         :  app_info.path,
    'version'      : '16.0.4900.1000',
    'append'       : "webservices\conversionservices\1033",
    'file'         : 'wwintl.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4475596',
    'path'         :  app_info.path,
    'version'      : '16.0.10350.20000',
    'append'       : "bin",
    'file'         : 'microsoft.sharepoint.publishing.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4464557',
    'path'         :  app_info.path,
    'version'      : '16.0.10350.20000',
    'append'       : "webservices\conversionservices\1033",
    'file'         : 'wwintl.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-09',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
