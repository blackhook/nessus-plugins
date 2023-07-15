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
  script_id(110993);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2018-8299", "CVE-2018-8300", "CVE-2018-8323");
  script_bugtraq_id(104610, 104611, 104614);
  script_xref(name:"MSKB", value:"4022243");
  script_xref(name:"MSKB", value:"4022228");
  script_xref(name:"MSKB", value:"4022235");
  script_xref(name:"MSFT", value:"MS18-4022243");
  script_xref(name:"MSFT", value:"MS18-4022228");
  script_xref(name:"MSFT", value:"MS18-4022235");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (July 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft SharePoint when the software fails to check
    the source markup of an application package. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the SharePoint
    application pool and the SharePoint server farm account.
    Exploitation of this vulnerability requires that a user
    uploads a specially crafted SharePoint application
    package to an affected versions of SharePoint. The
    security update addresses the vulnerability by
    correcting how SharePoint checks the source markup of
    application packages. (CVE-2018-8300)

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
    Server properly sanitizes web requests. (CVE-2018-8299,
    CVE-2018-8323)");
  # https://support.microsoft.com/en-us/help/4022243/description-of-the-security-update-for-sharepoint-foundation-2013-july
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b68cf0a6");
  # https://support.microsoft.com/en-us/help/4022228/description-of-the-security-update-for-sharepoint-server-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba29bfa0");
  # https://support.microsoft.com/en-us/help/4022235/description-of-the-security-update-for-sharepoint-server-2013-july-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6a7940a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4022243
  -KB4022228
  -KB4022235");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4022235',
    'path'         :  app_info.path,
    'version'      : '15.0.4905.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'osafehtm.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4022243',
    'path'         :  app_info.path,
    'version'      : '15.0.5049.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "Microsoft Shared\Web Server Extensions\15\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4022228',
    'path'         :  app_info.path,
    'version'      : '16.0.4717.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\16\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-07',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
