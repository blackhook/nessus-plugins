#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159678);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2022-24472", "CVE-2022-26901");
  script_xref(name:"MSKB", value:"5002191");
  script_xref(name:"MSFT", value:"MS22-5002191");
  script_xref(name:"IAVA", value:"2022-A-0141-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server Subscription Edition (April 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server Subscription Edition installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server Subscription Edition installation on the remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities:

- A session spoofing vulnerability exists. An attacker can
exploit this to perform actions with the privileges of
another user. (CVE-2022-24472)

- A remote code execution vulnerability. An attacker can
exploit this to bypass authentication and execute
unauthorized arbitrary commands. (CVE-2022-26901)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002191");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002191 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product'      : 'Subscription Edition',
    'edition'      : 'Server',
    'kb'           : '5002191',
    'path'         : app_info.hotfix_path,
    'version'      : '16.0.14931.20196',
    'append'       : 'microsoft shared\\web server extensions\\16\\isapi',
    'file'         : 'Microsoft.SharePoint.Portal.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server Subscription Edition'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS22-04',
  constraints:kb_checks, 
  severity:SECURITY_WARNING
);
