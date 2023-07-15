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
  script_id(105696);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id(
    "CVE-2018-0789",
    "CVE-2018-0790",
    "CVE-2018-0792",
    "CVE-2018-0797",
    "CVE-2018-0799"
  );
  script_bugtraq_id(
    102381,
    102391,
    102394,
    102406,
    102411
  );
  script_xref(name:"MSKB", value:"3114998");
  script_xref(name:"MSKB", value:"3141547");
  script_xref(name:"MSKB", value:"4011579");
  script_xref(name:"MSKB", value:"4011599");
  script_xref(name:"MSKB", value:"4011609");
  script_xref(name:"MSKB", value:"4011642");
  script_xref(name:"MSKB", value:"4011653");
  script_xref(name:"MSFT", value:"MS18-3114998");
  script_xref(name:"MSFT", value:"MS18-3141547");
  script_xref(name:"MSFT", value:"MS18-4011579");
  script_xref(name:"MSFT", value:"MS18-4011599");
  script_xref(name:"MSFT", value:"MS18-4011609");
  script_xref(name:"MSFT", value:"MS18-4011642");
  script_xref(name:"MSFT", value:"MS18-4011653");
  script_xref(name:"IAVA", value:"2018-A-0009-S");

  script_name(english:"Security Update for Microsoft SharePoint Server (January 2018)");
  script_summary(english:"Checks for Microsoft security update.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing security updates.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing security
updates. It is, therefore, affected by the following
vulnerabilities :

  - An elevation of privilege vulnerability exists when Microsoft
    SharePoint Server does not properly sanitize a specially crafted
    web request to an affected SharePoint server. An authenticated
    attacker could exploit the vulnerability by sending a specially
    crafted request to an affected SharePoint server.
    (CVE-2018-0789, CVE-2018-0790)

  - A remote code execution vulnerability exists in Microsoft Office
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2018-0792)

  - An Office RTF remote code execution vulnerability exists in
    Microsoft Office software when the Office software fails to
    properly handle RTF files. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the context of the
    current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected
    system. An attacker could then install programs; view, change, or
    delete data; or create new accounts with full user rights. Users
    whose accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate with
    administrative user rights. (CVE-2018-0797)

  - A cross-site-scripting (XSS) vulnerability exists when Microsoft
    Access does not properly sanitize inputs to image fields edited
    within Design view. An attacker could exploit the vulnerability by
    sending a specially crafted file to a victim, or by hosting the
    file on a web server. (CVE-2018-0799)");
  # https://support.microsoft.com/en-us/help/3114998/descriptionofthesecurityupdateforsharepointserver2010january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd18318b");
  # https://support.microsoft.com/en-us/help/3141547/descriptionofthesecurityupdateforsharepointfoundation2010january9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cab3ede");
  # https://support.microsoft.com/en-us/help/4011579/descriptionofthesecurityupdateforsharepointserver2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1d4a69b");
  # https://support.microsoft.com/en-us/help/4011599/descriptionofthesecurityupdateforsharepointserver2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0ca2685");
  # https://support.microsoft.com/en-us/help/4011609/descriptionofthesecurityupdateforsharepointserver2010january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8b7c595");
  # https://support.microsoft.com/en-us/help/4011642/descriptionofthesecurityupdateforsharepointenterpriseserver2016january
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7823ab97");
  # https://support.microsoft.com/en-us/help/4011653/descriptionofthesecurityupdateforsharepointfoundation2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf2ca8ef");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0789
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d3749df");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0790
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53edad91");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0792
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54f02eaf");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0797
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a757a23");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0799
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9007faa3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - KB3114998
  - KB3141547
  - KB4011579
  - KB4011599
  - KB4011609
  - KB4011642
  - KB4011653");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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
    'kb'           : '3114998',
    'path'         :  app_info.path,
    'version'      : '14.0.7192.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\14\ISAPI",
    'file'         : 'microsoft.sharepoint.portal.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'edition'      : 'Server',
    'kb'           : '4011609',
    'path'         :  app_info.path,
    'version'      : '14.0.7192.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'edition'      : 'Foundation',
    'kb'           : '3141547',
    'path'         :  app_info.path,
    'version'      : '14.0.7184.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Microsoft Shared\SERVER14\Server Setup Controller",
    'file'         : 'wsssetup.dll',
    'product_name' : 'Microsoft SharePoint Foundation 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4011579',
    'path'         :  app_info.path,
    'version'      : '15.0.4997.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4011599',
    'path'         :  app_info.path,
    'version'      : '15.0.4997.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Access.Server.Application\v4.0_15.0.0.0__71e9bce111e9429c",
    'file'         : 'Microsoft.Office.Access.Server.Application.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4011653',
    'path'         :  app_info.path,
    'version'      : '15.0.4997.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4011642',
    'path'         :  app_info.path,
    'version'      : '16.0.4639.1002',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-01',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
