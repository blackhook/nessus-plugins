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
  script_id(103141);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2017-8629",
    "CVE-2017-8631",
    "CVE-2017-8742",
    "CVE-2017-8743",
    "CVE-2017-8745"
  );
  script_bugtraq_id(
    100725,
    100741,
    100746,
    100751,
    100753
  );
  script_xref(name:"MSKB", value:"4011056");
  script_xref(name:"MSKB", value:"4011117");
  script_xref(name:"MSKB", value:"3213560");
  script_xref(name:"MSKB", value:"4011113");
  script_xref(name:"MSKB", value:"4011127");
  script_xref(name:"MSKB", value:"3191831");
  script_xref(name:"MSFT", value:"MS17-4011056");
  script_xref(name:"MSFT", value:"MS17-4011117");
  script_xref(name:"MSFT", value:"MS17-3213560");
  script_xref(name:"MSFT", value:"MS17-4011113");
  script_xref(name:"MSFT", value:"MS17-4011127");
  script_xref(name:"MSFT", value:"MS17-3191831");
  script_xref(name:"IAVA", value:"2017-A-0274");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (September 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user. Exploitation of
    this vulnerability requires that a user open a specially
    crafted file with an affected version of Microsoft
    Office software. In an email attack scenario, an
    attacker could exploit the vulnerability by sending the
    specially crafted file to the user and convincing the
    user to open the file. In a web-based attack scenario,
    an attacker could host a website (or leverage a
    compromised website that accepts or hosts user-provided
    content) that contains a specially crafted file that is
    designed to exploit the vulnerability. However, an
    attacker would have no way to force the user to visit
    the website. Instead, an attacker would have to convince
    the user to click a link, typically by way of an
    enticement in an email or Instant Messenger message, and
    then convince the user to open the specially crafted
    file. The security update addresses the vulnerability by
    correcting how Microsoft Office handles files in memory.
    (CVE-2017-8631)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    Exploitation of the vulnerability requires that a user
    open a specially crafted file with an affected version
    of Microsoft Office software. In an email attack
    scenario, an attacker could exploit the vulnerability by
    sending the specially crafted file to the user and
    convincing the user to open the file. In a web-based
    attack scenario, an attacker could host a website (or
    leverage a compromised website that accepts or hosts
    user-provided content) that contains a specially crafted
    file designed to exploit the vulnerability. An attacker
    would have no way to force users to visit the website.
    Instead, an attacker would have to convince users to
    click a link, typically by way of an enticement in an
    email or instant message, and then convince them to open
    the specially crafted file. Note that the Preview Pane
    is not an attack vector for this vulnerability. The
    security update addresses the vulnerability by
    correcting how Office handles objects in memory.
    (CVE-2017-8742, CVE-2017-8743)

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
    Server properly sanitizes web requests. (CVE-2017-8629)

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
    Server properly sanitizes web requests. (CVE-2017-8745)");
  # https://support.microsoft.com/en-us/help/4011056/descriptionofthesecurityupdateforsharepointserver2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?604636cb");
  # https://support.microsoft.com/en-us/help/4011117/descriptionofthesecurityupdateforsharepointfoundation2013september12-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a44abe21");
  # https://support.microsoft.com/en-us/help/3213560/descriptionofthesecurityupdateforsharepointserver2013september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af7fb55b");
  # https://support.microsoft.com/en-us/help/4011113/descriptionofthesecurityupdateforsharepointserver2013september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d79043bd");
  # https://support.microsoft.com/en-us/help/4011127/descriptionofthesecurityupdateforsharepointserver2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cbef33e");
  # https://support.microsoft.com/en-us/help/3191831/descriptionofthesecurityupdateforsharepointserver2007september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb6ab180");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011056
  -KB4011117
  -KB3213560
  -KB4011113
  -KB4011127
  -KB3191831");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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
    'product'      : '2007',
    'kb'           : '3191831',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '12.0.6776.5000',
    'min_version'  : '12.0.0.0',
    'append'       : "Bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Excel Services for SharePoint Server 2007 SP3'
  },
  {
    'product'      : '2010',
    'kb'           : '4011056',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '14.0.7188.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Excel Services for SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'kb'           : '3213560',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.4961.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'ppserver.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 Service Pack 1'
  },
  {
    'product'      : '2013',
    'kb'           : '4011217',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.4936.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'htmlutil.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 Service Pack 1'
  },
  {
    'product'      : '2013',
    'kb'           : '4011117',
    'path'         :  app_info.path,
    'edition'      : 'Foundation',
    'version'      : '15.0.4963.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft Sharepoint Foundation 2013 Service Pack 1'
  },
  {
    'product'      : '2016',
    'kb'           : '4011127',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '16.0.4588.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS17-09',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
