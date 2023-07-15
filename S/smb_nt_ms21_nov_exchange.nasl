#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154999);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id("CVE-2021-41349", "CVE-2021-42305", "CVE-2021-42321");
  script_xref(name:"IAVA", value:"2021-A-0543-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/01");
  script_xref(name:"MSKB", value:"5007409");
  script_xref(name:"MSFT", value:"MS21-5007409");

  script_name(english:"Security Updates for Exchange (November 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2021-41349, CVE-2021-42305)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-42321)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5007409");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5007409 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42321");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange Server ChainedSerializationBinder RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'unsupported_cu' : 22, 
    'min_version': '15.0.1497.0', 
    'fixed_version': '15.0.1497.26'
  },
  {
    'product' : '2016', 
    'unsupported_cu' : 20, 
    'min_version': '15.1.2308.0', 
    'fixed_version': '15.1.2308.20'
  },
  {
    'product': '2016',
    'unsupported_cu': 20,
    'min_version': '15.1.2375.0',
    'fixed_version': '15.1.2375.17'
  },
  {
    'product' : '2019', 
    'unsupported_cu' : 9,
    'min_version': '15.2.922.0',
    'fixed_version': '15.2.922.19'
  },
  {
    'product' : '2019', 
    'unsupported' : 9,
    'min_version': '15.2.986.0',
    'fixed_version': '15.2.986.14'
  }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info, 
  bulletin:'MS21-11',
  constraints:constraints, 
  severity:SECURITY_WARNING
);
