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
  script_id(105190);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id("CVE-2017-11936");
  script_bugtraq_id(102068);
  script_xref(name:"MSKB", value:"4011576");
  script_xref(name:"MSFT", value:"MS17-4011576");
  script_xref(name:"IAVA", value:"2017-A-0363-S");

  script_name(english:"Security Update for Microsoft SharePoint Server 2016 (December 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server or Microsoft Project Server
installation on the remote host is missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An elevation of privilege vulnerability exists when Microsoft
    SharePoint Server does not properly sanitize a specially crafted
    web request to an affected SharePoint server. An authenticated
    attacker could exploit the vulnerability by sending a specially
    crafted request to an affected SharePoint server.
    (CVE-2017-11936)");
  # https://support.microsoft.com/en-us/help/4011576/descriptionofthesecurityupdateforsharepointserver2016december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f43e5cb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security update KB4011576 to address this
issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

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
    'product'      : '2016',
    'kb'           : '4011576',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '16.0.0.0',
    'version'      : '16.0.4627.1000',
    'edition'      : 'Server',
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS17-12',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
