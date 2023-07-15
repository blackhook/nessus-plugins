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
  script_id(129731);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2019-1070",
    "CVE-2019-1328",
    "CVE-2019-1329",
    "CVE-2019-1330",
    "CVE-2019-1331"
  );
  script_xref(name:"MSKB", value:"4462176");
  script_xref(name:"MSKB", value:"4462215");
  script_xref(name:"MSKB", value:"4475608");
  script_xref(name:"MSKB", value:"4484111");
  script_xref(name:"MSKB", value:"4484110");
  script_xref(name:"MSKB", value:"4484122");
  script_xref(name:"MSKB", value:"4484131");
  script_xref(name:"MSFT", value:"MS19-4462176");
  script_xref(name:"MSFT", value:"MS19-4462215");
  script_xref(name:"MSFT", value:"MS19-4475608");
  script_xref(name:"MSFT", value:"MS19-4484110");
  script_xref(name:"MSFT", value:"MS19-4484111");
  script_xref(name:"MSFT", value:"MS19-4484122");
  script_xref(name:"MSFT", value:"MS19-4484131");
  script_xref(name:"IAVA", value:"2019-A-0359-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server (Oct 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

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
    Server properly sanitizes web requests. (CVE-2019-1070)
  
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
    Server properly sanitizes web requests. (CVE-2019-1328)

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
    Server properly sanitizes web requests. (CVE-2019-1329)

  - An elevation of privilege vulnerability exists in
    Microsoft SharePoint. An attacker who successfully
    exploited this vulnerability could attempt to
    impersonate another user of the SharePoint server.
    (CVE-2019-1330)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-1331)");
  # https://support.microsoft.com/en-us/help/4475608/security-update-for-sharepoint-enterprise-server-2013-october-8-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73c5cc63");
  # https://support.microsoft.com/en-us/help/4462176/security-update-for-sharepoint-server-2010-october-8-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?707ff09a");
  # https://support.microsoft.com/en-us/help/4484122/security-update-for-sharepoint-foundation-2013-october-8-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9af99b6");
  # https://support.microsoft.com/en-us/help/4462215/security-update-for-sharepoint-enterprise-server-2013-october-8-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd9d4866");
  # https://support.microsoft.com/en-us/help/4484111/security-update-for-sharepoint-enterprise-server-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fc6eac4");
  # https://support.microsoft.com/en-us/help/4484110/security-update-for-sharepoint-server-2019-october-8-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b7b956");
  # https://support.microsoft.com/en-us/help/4484131/security-update-for-sharepoint-foundation-2010-october-8-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cade65c4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462176
  -KB4462215
  -KB4475608
  -KB4484110
  -KB4484111
  -KB4484122
  -KB4484131");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'kb'           : '4462176',
    'path'         :  app_info.path,
    'version'      : '14.0.7239.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'edition'      : 'Foundation',
    'kb'           : '4484131',
    'path'         :  app_info.path,
    'version'      : '14.0.7239.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "microsoft shared\web server extensions\14\bin",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4462215',
    'path'         :  app_info.path,
    'version'      : '15.0.5179.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4475608',
    'path'         :  app_info.path,
    'version'      : '15.0.5179.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "transformapps",
    'file'         : 'docxpageconverter.exe',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4484122',
    'path'         :  app_info.path,
    'version'      : '15.0.5111.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\web server extensions\15\bin",
    'file'         : 'csisrv.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Enterprise',
    'kb'           : '4484111',
    'path'         :  app_info.path,
    'version'      : '16.0.4912.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "webservices\conversionservices",
    'file'         : 'msoserver.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Enterprise',
    'kb'           : '4484110',
    'path'         :  app_info.path,
    'version'      : '16.0.10351.20000',
    'min_version'  : '16.0.10000.0',
    'append'       : "bin",
    'file'         : 'microsoft.sharepoint.publishing.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-10',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
