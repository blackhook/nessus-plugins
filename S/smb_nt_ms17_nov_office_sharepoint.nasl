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
  script_id(104570);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2017-11876");
  script_bugtraq_id(101754);
  script_xref(name:"MSKB", value:"4011267");
  script_xref(name:"MSKB", value:"4011244");
  script_xref(name:"MSKB", value:"4011245");
  script_xref(name:"MSKB", value:"4011257");
  script_xref(name:"MSFT", value:"MS17-4011267");
  script_xref(name:"MSFT", value:"MS17-4011244");
  script_xref(name:"MSFT", value:"MS17-4011245");
  script_xref(name:"MSFT", value:"MS17-4011257");
  script_xref(name:"IAVA", value:"2017-A-0337-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server and Microsoft Project Server (November 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An elevation of privilege vulnerability exists in
    Microsoft Project when Microsoft Project Server does not
    properly manage user sessions. For this Cross-site
    Request Forgery(CSRF/XSRF) vulnerability to be
    exploited, the victim must be authenticated to (logged
    on) the target site.  (CVE-2017-11876)

  - A remote code execution vulnerability exists when a
    user opens a specially crafted office file. 
    (ADV170020).");
  # https://support.microsoft.com/en-us/help/4011267/descriptionofthesecurityupdateforwordautomationservicesonsharepointser
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?441fc23d");
  # https://support.microsoft.com/en-us/help/4011244/descriptionofthesecurityupdateforsharepointserver2016november14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fbd25b4");
  # https://support.microsoft.com/en-us/help/4011245/description-of-the-security-update-for-sharepoint-enterprise-server-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42a3373f");
  # https://support.microsoft.com/en-us/help/4011257/description-of-the-security-update-for-project-server-2013-november-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e718850e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011267
  -KB4011244
  -KB4011245
  -KB4011257");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11876");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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
    'kb'           : '4011267',
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
    'kb'           : '4011245',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.4963.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'msores.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 Service Pack 1'
  },
  {
    'product'      : '2013',
    'kb'           : '4011257',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.4981.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Bin",
    'file'         : 'Microsoft.Office.Project.Server.Library.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 Service Pack 1'
  },
  {
    'product'      : '2016',
    'kb'           : '4011257',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '16.0.4615.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS17-11',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);