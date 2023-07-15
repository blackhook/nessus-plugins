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
  script_id(102272);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id("CVE-2017-8654");
  script_bugtraq_id(100064);
  script_xref(name:"MSKB", value:"2956077");
  script_xref(name:"MSFT", value:"MS17-2956077");

  script_name(english:"Security Update for Microsoft SharePoint Server 2010 (August 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installed on the remote Windows host
is missing security update 2956077. It is, therefore, affected by a
cross-site scripting (XSS) vulnerability when Microsoft SharePoint
Server does not properly sanitize a specially crafted web request to
an affected SharePoint server. An authenticated attacker could exploit
the vulnerability by sending a specially crafted request to an
affected SharePoint server. The attacker who successfully exploited
the vulnerability could then perform cross-site scripting attacks on
affected systems and run script in the security context of the current
user. The attacks could allow the attacker to read content that the
attacker is not authorized to read, use the victim's identity to take
actions on the SharePoint site on behalf of the user, such as change
permissions and delete content, and inject malicious content in the
browser of the user.");
  # https://support.microsoft.com/en-us/help/2956077/description-of-the-security-update-for-sharepoint-server-2010-august-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79cb8f9d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for SharePoint Server 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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
    'kb'           : '2956077',
    'path'         :  app_info.path,
    'append'       : "Common Files\Microsoft Shared\SERVER14\Server Setup Controller",
    'min_version'  : '14.0.0.0',
    'version'      : '14.0.7184.5000',
    'edition'      : 'Server',
    'file'         : 'svrsetup.dll',
    'product_name' : 'Microsoft Office SharePoint Server 2010 SP2'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS17-08',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);

