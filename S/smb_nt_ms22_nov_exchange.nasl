#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167281);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2022-41040",
    "CVE-2022-41078",
    "CVE-2022-41079",
    "CVE-2022-41080",
    "CVE-2022-41082",
    "CVE-2022-41123"
  );
  script_xref(name:"MSFT", value:"MS22-5019758");
  script_xref(name:"MSKB", value:"5019758");
  script_xref(name:"IAVA", value:"2022-A-0474-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/21");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/31");
  script_xref(name:"CEA-ID", value:"CEA-2022-0031");

  script_name(english:"Security Updates for Microsoft Exchange Server (Nov 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities as referenced in the Nov, 2022 security bulletin.

  - Microsoft Exchange Server Spoofing Vulnerability (CVE-2022-41078, CVE-2022-41079)

  - Microsoft Exchange Server Elevation of Privilege Vulnerability (CVE-2022-41040, CVE-2022-41080, 
    CVE-2022-41123)

  - Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2022-41082)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5019758");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5019758");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41080");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange ProxyNotShell RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints =
[
  {
    'product' : '2013',
    'cu': 23,
    'unsupported_cu': 22,
    'fixed_version': '15.0.1497.44',
    'kb': '5019076'
  },
  {
    'product' : '2016',
    'cu': 22,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2375.37',
    'kb': '5019758'
  },
  {
    'product': '2016',
    'cu': 23,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2507.16',
    'kb': '5019758'
  },
  {
    'product' : '2019',
    'cu': 11,
    'unsupported_cu': 10,
    'fixed_version': '15.2.986.36',
    'kb': '5019758'
  },
  {
    'product' : '2019',
    'cu': 12,
    'unsupported_cu': 10,
    'fixed_version': '15.2.1118.20',
    'kb': '5019758'
  }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS22-11',
  constraints:constraints,
  severity:SECURITY_HOLE
);
