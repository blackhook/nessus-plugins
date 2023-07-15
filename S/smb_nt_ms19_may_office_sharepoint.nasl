
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
  script_id(125227);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2019-0949",
    "CVE-2019-0950",
    "CVE-2019-0951",
    "CVE-2019-0952",
    "CVE-2019-0956",
    "CVE-2019-0957",
    "CVE-2019-0958",
    "CVE-2019-0963"
  );
  script_bugtraq_id(
    108198,
    108201,
    108203,
    108209,
    108213,
    108215,
    108216,
    108218
  );
  script_xref(name:"MSKB", value:"4464573");
  script_xref(name:"MSKB", value:"4464564");
  script_xref(name:"MSKB", value:"4464556");
  script_xref(name:"MSKB", value:"4464549");
  script_xref(name:"MSFT", value:"MS19-4464573");
  script_xref(name:"MSFT", value:"MS19-4464564");
  script_xref(name:"MSFT", value:"MS19-4464556");
  script_xref(name:"MSFT", value:"MS19-4464549");
  script_xref(name:"CEA-ID", value:"CEA-2019-0326");

  script_name(english:"Security Updates for Microsoft SharePoint Server (May 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
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
    Server properly sanitizes web requests. (CVE-2019-0956)

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
    Server properly sanitizes web requests. (CVE-2019-0957,
    CVE-2019-0958)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint Server when it fails to properly
    identify and filter unsafe ASP.Net web controls. An
    authenticated attacker who successfully exploited the
    vulnerability could use a specially crafted page to
    perform actions in the security context of the
    SharePoint application pool process.  (CVE-2019-0952)

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
    Server properly sanitizes web requests. (CVE-2019-0963)

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
    Server properly sanitizes web requests. (CVE-2019-0949,
    CVE-2019-0950, CVE-2019-0951)");
  # https://support.microsoft.com/en-ie/help/4464573/description-of-the-security-update-for-sharepoint-foundation-2010-may
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd24cf15");
  # https://support.microsoft.com/en-ie/help/4464564/description-of-the-security-update-for-sharepoint-foundation-2013-may
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10270ee1");
  # https://support.microsoft.com/en-us/help/4464556/description-of-the-security-update-for-sharepoint-server-2019-may-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f5a91df");
  # https://support.microsoft.com/en-us/help/4464549/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f305a65b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4464573
  -KB4464564
  -KB4464556
  -KB4464549");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0958");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

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
    'kb'           : '4464573',
    'path'         :  app_info.path,
    'version'      : '14.0.7234.5000',
    'append'       : "microsoft shared\web server extensions\14\isapi",
    'file'         : 'microsoft.sharepoint.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4464564',
    'path'         :  app_info.path,
    'version'      : '15.0.4981.1000',
    'append'       : "microsoft shared\Web Server Extensions\15\config\bin",
    'file'         : 'stssoap.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4464549',
    'path'         :  app_info.path,
    'version'      : '16.0.4849.1000',
    'append'       : "TransformApps",
    'file'         : 'docxpageconverter.exe',
    'product_name' : 'Microsoft SharePoint Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4464556',
    'path'         :  app_info.path,
    'version'      : '16.0.10345.12101',
    'append'       : "BIN",
    'file'         : 'ascalc.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-05',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
