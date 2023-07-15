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
  script_id(126584);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id("CVE-2019-1006", "CVE-2019-1134");
  script_bugtraq_id(108978, 109028);
  script_xref(name:"MSKB", value:"4475510");
  script_xref(name:"MSKB", value:"4475520");
  script_xref(name:"MSKB", value:"4475522");
  script_xref(name:"MSKB", value:"4475527");
  script_xref(name:"MSKB", value:"4475529");
  script_xref(name:"MSFT", value:"MS19-4475510");
  script_xref(name:"MSFT", value:"MS19-4475520");
  script_xref(name:"MSFT", value:"MS19-4475522");
  script_xref(name:"MSFT", value:"MS19-4475527");
  script_xref(name:"MSFT", value:"MS19-4475529");

  script_name(english:"Security Updates for Microsoft SharePoint Server (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An authentication bypass vulnerability exists in Windows
    Communication Foundation (WCF) and Windows Identity
    Foundation (WIF), allowing signing of SAML tokens with
    arbitrary symmetric keys. This vulnerability allows an
    attacker to impersonate another user, which can lead to
    elevation of privileges. The vulnerability exists in
    WCF, WIF 3.5 and above in .NET Framework, WIF 1.0
    component in Windows, WIF Nuget package, and WIF
    implementation in SharePoint. An unauthenticated
    attacker can exploit this by signing a SAML token with
    any arbitrary symmetric key. This security update
    addresses the issue by ensuring all versions of WCF and
    WIF validate the key used to sign SAML tokens correctly.
    (CVE-2019-1006)

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
    Server properly sanitizes web requests. (CVE-2019-1134)");
  # https://support.microsoft.com/en-us/help/4475520/security-update-for-sharepoint-enterprise-server-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccb4bdba");
  # https://support.microsoft.com/en-us/help/4475522/security-update-for-sharepoint-enterprise-server-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11471b7c");
  # https://support.microsoft.com/en-us/help/4475527/security-update-for-sharepoint-foundation-2013-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6efc6d4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue: 
  -KB4475510 
  -KB4475520
  -KB4475522
  -KB4475527
  -KB4475529");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

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
    'kb'           : '4475510',
    'path'         :  app_info.path,
    'version'      : '14.0.7235.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "microsoft shared\web server extensions\14\isapi",
    'file'         : 'microsoft.sharepoint.dll',
    'product_name' : 'Microsoft SharePoint Foundaiton Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4475522',
    'path'         :  app_info.path,
    'version'      : '15.0.5151.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "TransformApps",
    'file'         : 'docxpageconverter.exe',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4475527',
    'path'         :  app_info.path,
    'version'      : '15.0.5111.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\web server extensions\15\bin",
    'file'         : 'csisrv.dll',
    'product_name' : 'Microsoft SharePoint Foundaiton Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4475520',
    'path'         :  app_info.path,
    'version'      : '16.0.4867.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "bin",
    'file'         : 'microsoft.sharepoint.publishing.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4475529',
    'path'         :  app_info.path,
    'version'      : '16.0.10348.12104',
    'min_version'  : '16.0.10000.0',
    'append'       : "microsoft shared\web server extensions\15\bin",
    'file'         : 'microsoft.sharepoint.publishing.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-07',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
