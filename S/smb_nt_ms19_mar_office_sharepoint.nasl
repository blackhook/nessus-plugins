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
  script_id(122859);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id("CVE-2019-0604", "CVE-2019-0778");
  script_bugtraq_id(106914, 107226);
  script_xref(name:"MSKB", value:"4462184");
  script_xref(name:"MSKB", value:"4462199");
  script_xref(name:"MSKB", value:"4462202");
  script_xref(name:"MSKB", value:"4462208");
  script_xref(name:"MSKB", value:"4462211");
  script_xref(name:"MSKB", value:"4462217");
  script_xref(name:"MSKB", value:"4462219");
  script_xref(name:"MSKB", value:"4462228");
  script_xref(name:"MSFT", value:"MS19-4462184");
  script_xref(name:"MSFT", value:"MS19-4462199");
  script_xref(name:"MSFT", value:"MS19-4462202");
  script_xref(name:"MSFT", value:"MS19-4462208");
  script_xref(name:"MSFT", value:"MS19-4462211");
  script_xref(name:"MSFT", value:"MS19-4462217");
  script_xref(name:"MSFT", value:"MS19-4462219");
  script_xref(name:"MSFT", value:"MS19-4462228");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (March 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerabilities:

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
    Server properly sanitizes web requests. (CVE-2019-0778)

  - A remote code execution vulnerability exists in Microsoft
    SharePoint when the software fails to check the source markup of
    an application package. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the context of the
    SharePoint application pool and the SharePoint server farm
    account. Exploitation of this vulnerability requires that a user
    uploads a specially crafted SharePoint application package to an
    affected versions of SharePoint.(CVE-2019-0604)");
  # https://support.microsoft.com/en-us/help/4462184/description-of-the-security-update-for-sharepoint-server-2010-march-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3eb0a95");
  # https://support.microsoft.com/en-us/help/4462202/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fa2dd75");
  # https://support.microsoft.com/en-us/help/4462208/description-of-the-security-update-for-sharepoint-foundation-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5d491e7");
  # https://support.microsoft.com/en-us/help/4462211/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ea0d7b4");
  # https://support.microsoft.com/en-us/help/4462199/description-of-the-security-update-for-sharepoint-server-2019-march-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91b3484a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462184
  -KB4462199
  -KB4462202
  -KB4462208
  -KB4462211");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");

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
    'edition'      : 'Server',
    'kb'           : '4462184',
    'path'         :  app_info.path,
    'version'      : '14.0.7231.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\14\ISAPI",
    'file'         : 'microsoft.sharepoint.portal.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4462202',
    'path'         :  app_info.path,
    'version'      : '15.0.5119.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'msoserver.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4462208',
    'path'         :  app_info.path,
    'version'      : '15.0.5119.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\15\bin",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4462211',
    'path'         :  app_info.path,
    'version'      : '16.0.4822.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4462199',
    'path'         :  app_info.path,
    'version'      : '16.0.10342.12113',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-03',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
