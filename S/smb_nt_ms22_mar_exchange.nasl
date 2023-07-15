#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158786);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-23277", "CVE-2022-24463");
  script_xref(name:"MSKB", value:"5010324");
  script_xref(name:"MSKB", value:"5012698");
  script_xref(name:"MSFT", value:"MS22-5010324");
  script_xref(name:"MSFT", value:"MS22-5012698");
  script_xref(name:"IAVA", value:"2022-A-0110-S");

  script_name(english:"Security Updates for Exchange (March 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security updates. It is, therefore, affected by 
multiple vulnerabilities including the following:

  - A remote code execution vulnerability exists in Exchange. An authenticated, remote attacker can exploit this to 
    bypass authentication and execute arbitrary commands (CVE-2022-23277).

  - An information disclosure vulnerability exists in Exchange. An authenticated, remote attacker can exploit this 
    to disclose the contents of files on the exchange server (CVE-2022-24463).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012698");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5010324");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5012698 and KB5010324 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23277");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange Server ChainedSerializationBinder RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/10");

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
    'fixed_version': '15.00.1497.33',
    'kb': '5010324'
  },
  {
    'product' : '2016',
    'cu': 21,
    'unsupported_cu': 20,
    'fixed_version': '15.01.2308.27',
    'kb': '5012698'
  },
  {
    'product': '2016',
    'cu': 22,
    'unsupported_cu': 20,
    'fixed_version': '15.01.2375.24',
    'kb': '5012698'
  },
  {
    'product' : '2019',
    'cu': 10,
    'unsupported_cu': 9,
    'fixed_version': '15.02.922.27',
    'kb': '5012698'
  },
  {
    'product' : '2019',
    'cu': 11,
    'unsupported_cu': 9,
    'fixed_version': '15.02.986.22',
    'kb': '5012698'
  }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS22-03',
  constraints:constraints,
  severity:SECURITY_WARNING
);
