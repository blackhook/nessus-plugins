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
  script_id(118925);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id(
    "CVE-2018-8539",
    "CVE-2018-8568",
    "CVE-2018-8572",
    "CVE-2018-8577",
    "CVE-2018-8578"
  );
  script_xref(name:"MSKB", value:"4461483");
  script_xref(name:"MSKB", value:"4461501");
  script_xref(name:"MSKB", value:"4461520");
  script_xref(name:"MSKB", value:"4461511");
  script_xref(name:"MSKB", value:"4011190");
  script_xref(name:"MSKB", value:"4461513");
  script_xref(name:"MSFT", value:"MS18-4461483");
  script_xref(name:"MSFT", value:"MS18-4461501");
  script_xref(name:"MSFT", value:"MS18-4461520");
  script_xref(name:"MSFT", value:"MS18-4461511");
  script_xref(name:"MSFT", value:"MS18-4011190");
  script_xref(name:"MSFT", value:"MS18-4461513");

  script_name(english:"Security Updates for Microsoft SharePoint Server (November 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8577)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2018-8539)

  - An information disclosure vulnerability exists when
    Microsoft SharePoint Server improperly discloses its
    folder structure when rendering specific web pages. An
    attacker who took advantage of this information
    disclosure could view the folder path of scripts loaded
    on the page. To take advantage of the vulnerability, an
    attacker would require access to the specific SharePoint
    page affected by this vulnerability. The security update
    addresses the vulnerability by correcting how scripts
    are referenced on some SharePoint pages. (CVE-2018-8578)

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
    Server properly sanitizes web requests. (CVE-2018-8568,
    CVE-2018-8572)");
  # https://support.microsoft.com/en-us/help/4461483/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82371ff4");
  # https://support.microsoft.com/en-us/help/4461501/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?725ac5ec");
  # https://support.microsoft.com/en-us/help/4461520/description-of-the-security-update-for-sharepoint-server-2010-november
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33c3f954");
  # https://support.microsoft.com/en-us/help/4461511/description-of-the-security-update-for-sharepoint-foundation-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a740ac2");
  # https://support.microsoft.com/en-us/help/4011190/description-of-the-security-update-for-sharepoint-server-2010-november
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73b8232d");
  # https://support.microsoft.com/en-us/help/4461513/description-of-the-security-update-for-sharepoint-server-2019-november
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6edad44");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4461483
  -KB4461501
  -KB4461520
  -KB4461511
  -KB4011190");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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
    'kb'           : '4461520',
    'path'         :  app_info.path,
    'version'      : '14.0.7224.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'msoserver.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2 (Word Automation Services)'
  },
  {
    'product'      : '2010',
    'edition'      : 'Server',
    'kb'           : '4011190',
    'path'         :  app_info.path,
    'version'      : '14.0.7224.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2 (Excel Service)'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4461483',
    'path'         :  app_info.path,
    'version'      : '15.0.4981.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\15\ISAPI",
    'file'         : 'Microsoft.Office.Server.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4461511',
    'path'         :  app_info.path,
    'version'      : '15.0.5085.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\15\BIN",
    'file'         : 'CsiSrv.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4461501',
    'path'         :  app_info.path,
    'version'      : '16.0.4771.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\16\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4461513',
    'path'         :  app_info.path,
    'version'      : '16.0.10338.12107',
    'min_version'  : '16.0.10337.0',
    'append'       : "microsoft shared\Web Server Extensions\16\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-11',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);

