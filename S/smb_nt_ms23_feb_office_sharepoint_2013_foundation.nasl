#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171508);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2023-21716", "CVE-2023-21717");
  script_xref(name:"MSKB", value:"5002347");
  script_xref(name:"MSFT", value:"MS23-5002347");
  script_xref(name:"IAVA", value:"2023-A-0084-S");

  script_name(english:"Security Updates for Microsoft SharePoint Foundation 2013 (February 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Foundation 2013 installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Foundation 2013 installation on the
remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2023-21716)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2023-21717)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002347");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002347 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21716");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'edition'      : 'Foundation',
    'sp'           : '1',
    'kb'           : '5002347',
    'path'         : app_info.hotfix_path,
    'version'      : '15.0.5529.1000',
    'append'       : 'microsoft shared\\web server extensions\\15\\bin',
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft Sharepoint Foundation 2013 SP1' 
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS23-02',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
