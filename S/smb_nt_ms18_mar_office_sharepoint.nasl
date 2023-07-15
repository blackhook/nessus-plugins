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
  script_id(108298);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2018-0909",
    "CVE-2018-0910",
    "CVE-2018-0911",
    "CVE-2018-0912",
    "CVE-2018-0913",
    "CVE-2018-0914",
    "CVE-2018-0915",
    "CVE-2018-0916",
    "CVE-2018-0917",
    "CVE-2018-0919",
    "CVE-2018-0921",
    "CVE-2018-0922",
    "CVE-2018-0923",
    "CVE-2018-0944",
    "CVE-2018-0947"
  );
  script_bugtraq_id(
    103279,
    103280,
    103281,
    103285,
    103290,
    103291,
    103293,
    103294,
    103296,
    103302,
    103304,
    103306,
    103308,
    103311,
    103314
  );
  script_xref(name:"MSKB", value:"4011688");
  script_xref(name:"MSKB", value:"4011705");
  script_xref(name:"MSKB", value:"4018293");
  script_xref(name:"MSKB", value:"4018305");
  script_xref(name:"MSKB", value:"4018304");
  script_xref(name:"MSKB", value:"4018298");
  script_xref(name:"MSFT", value:"MS18-4011688");
  script_xref(name:"MSFT", value:"MS18-4011705");
  script_xref(name:"MSFT", value:"MS18-4018293");
  script_xref(name:"MSFT", value:"MS18-4018305");
  script_xref(name:"MSFT", value:"MS18-4018304");
  script_xref(name:"MSFT", value:"MS18-4018298");
  script_xref(name:"IAVA", value:"2018-A-0077-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server and Microsoft Project Server (March 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2018-0919)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the Office software fails
    to properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-0922)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly verify
    tenant permissions. An authenticated attacker could
    exploit the vulnerability by sending a specially crafted
    request to an affected SharePoint server. The attacker
    who successfully exploited the vulnerability could
    elevate permissions such that they gain full rights to
    the affected tenant. These attacks could allow the
    attacker to read content that the attacker is not
    authorized to read, change permissions, and edit or
    delete content. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly checks tenant permissions.
    (CVE-2018-0947)

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
    Server properly sanitizes web requests. (CVE-2018-0909,
    CVE-2018-0910, CVE-2018-0911, CVE-2018-0912,
    CVE-2018-0913, CVE-2018-0914, CVE-2018-0915,
    CVE-2018-0916, CVE-2018-0917, CVE-2018-0921,
    CVE-2018-0923, CVE-2018-0944)");
  # https://support.microsoft.com/en-us/help/4011688/descriptionofthesecurityupdateforsharepointenterpriseserver2013march13
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f34768d");
  # https://support.microsoft.com/en-us/help/4011705/description-of-the-security-update-for-sharepoint-server-2010-march-13
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65e15493");
  # https://support.microsoft.com/en-us/help/4018293/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?176cb32d");
  # https://support.microsoft.com/en-us/help/4018305/descriptionofthesecurityupdateforprojectserver2013march13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6ec22a1");
  # https://support.microsoft.com/en-us/help/4018304/descriptionofthesecurityupdateforsharepointfoundation2013march13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34e3980f");
  # https://support.microsoft.com/en-us/help/4018298/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9c82a37");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011688
  -KB4011705
  -KB4018293
  -KB4018305
  -KB4018304
  -KB4018298");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0922");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'kb'           : '4011705',
    'path'         :  app_info.path,
    'version'      : '14.0.7195.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4018305',
    'path'         :  app_info.path,
    'version'      : '15.0.4514.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'microsoft.office.project.server.msg.dll',
    'product_name' : 'Microsoft Project Server 2013'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4011688',
    'path'         :  app_info.path,
    'version'      : '15.0.5015.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4018298',
    'path'         :  app_info.path,
    'version'      : '15.0.5011.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\ISAPI",
    'file'         : 'microsoft.office.server.search.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4018304',
    'path'         :  app_info.path,
    'version'      : '15.0.5015.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4018293',
    'path'         :  app_info.path,
    'version'      : '16.0.4666.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-03',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
