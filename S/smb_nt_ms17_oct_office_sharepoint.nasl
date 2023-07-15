#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103786);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id(
    "CVE-2017-11775",
    "CVE-2017-11777",
    "CVE-2017-11820",
    "CVE-2017-11826"
  );
  script_bugtraq_id(
    101097,
    101105,
    101155,
    101219
  );
  script_xref(name:"MSKB", value:"3213623");
  script_xref(name:"MSKB", value:"4011068");
  script_xref(name:"MSKB", value:"4011170");
  script_xref(name:"MSKB", value:"4011180");
  script_xref(name:"MSKB", value:"4011217");
  script_xref(name:"MSFT", value:"MS17-3213623");
  script_xref(name:"MSFT", value:"MS17-4011068");
  script_xref(name:"MSFT", value:"MS17-4011170");
  script_xref(name:"MSFT", value:"MS17-4011180");
  script_xref(name:"MSFT", value:"MS17-4011217");
  script_xref(name:"IAVA", value:"2017-A-0291-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (October 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists when
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
    Server properly sanitizes web requests. (CVE-2017-11775,
    CVE-2017-11777, CVE-2017-11820)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2017-11826)");
  # https://support.microsoft.com/en-us/help/4011117/descriptionofthesecurityupdateforsharepointfoundation2013september12-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a44abe21");
  # https://support.microsoft.com/en-us/help/4011068/security-update-for-word-automation-services-for-sharepoint
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9244fe07");
  # https://support.microsoft.com/en-us/help/4011170/description-of-the-security-update-for-sharepoint-server-2013-october
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd221883");
  # https://support.microsoft.com/en-us/help/4011180/descriptionofthesecurityupdateforsharepointfoundation2013october10-201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f914ba0b");
  # https://support.microsoft.com/en-us/help/4011217/security-update-for-sharepoint-enterprise-server-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aaee58c0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB3213623
  -KB4011068
  -KB4011170
  -KB4011180
  -KB4011217");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11826");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'kb'           : '3213623',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '14.0.7190.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Word Automation Services for SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'kb'           : '4011170',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.4921.1000',
    'min_version'  : '15.0.0.0',
    'file'         : 'tquery.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 Service Pack 1'
  },
  {
    'product'      : '2013',
    'kb'           : '4011068',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.4963.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'oartserver.dll',
    'product_name' : 'Office SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4011180',
    'path'         :  app_info.path,
    'edition'      : 'Foundation',
    'version'      : '15.0.4971.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft Sharepoint Foundation 2013 Service Pack 1'
  },
  {
    'product'      : '2016',
    'kb'           : '4011217',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '16.0.4588.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'ppserver.dll',
    'product_name' : 'Office SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS17-10',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
