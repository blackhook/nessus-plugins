#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168503);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id("CVE-2022-41061", "CVE-2022-41062", "CVE-2022-41103");
  script_xref(name:"MSKB", value:"5002291");
  script_xref(name:"MSFT", value:"MS22-5002291");
  script_xref(name:"IAVA", value:"2022-A-0481-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server Subscription Edition Language Pack (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server Subscription Edition installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server Subscription Edition installation on the remote host 
is missing a language pack security updates. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-41061,
    CVE-2022-41062)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2022-41103)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002291");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002291 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_language_detection.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var language_lists = get_kb_list('SMB/base_language_installs'); 
# Normally this is used as language_lists = make_list(language_lists);
# In this plugin, it only is checked to insure that we have language files on machine.
if (isnull(language_lists)) exit(1, 'Language File Scan Information not found');

language_lists = make_list(
'1025', 
'1026', 
'1027', 
'1028', 
'1029', 
'1030', 
'1031', 
'1032', 
'1035',
'1036',
'1037',
'1038',
'1040',
'1041',
'1042',
'1043',
'1044',
'1045',
'1046',
'1048',
'1049',
'1050',
'1051',
'1053',
'1054',
'1055',
'1057',
'1058',
'1060',
'1061',
'1062',
'1063',
'1066',
'1068',
'1069',
'1071',
'1081',
'1086',
'1087',
'1106',
'1110',
'2052',
'2070',
'2108',
'3082',
'5146',
'9242',
'10266'
);

var app_info = vcf::microsoft::sharepoint::get_app_info();
var kb_checks = 
[
  {
    'product'      : 'Subscription Edition',
    'edition'      : 'Server',
    'kb'           : '5002291',
    'path'         : app_info.path,
    'version'      : '16.0.15601.20238',
    'append'       : 'bin\\*',
    'file'         : 'mssmsg.dll',
    'language'     : language_lists,
    'product_name' : 'Microsoft SharePoint Enterprise Server Subscription Edition'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS22-11',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
