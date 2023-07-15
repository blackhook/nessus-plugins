#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149393);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/08");

  script_cve_id(
    "CVE-2021-31195",
    "CVE-2021-31198",
    "CVE-2021-31207",
    "CVE-2021-31209"
  );
  script_xref(name:"MSKB", value:"5003435");
  script_xref(name:"MSFT", value:"MS21-5003435");
  script_xref(name:"IAVA", value:"2021-A-0221-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0040");

  script_name(english:"Security Updates for Exchange (May 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities:
  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2021-31207)
  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-31195,
    CVE-2021-31198)
  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2021-31209)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-may-11-2021-kb5003435-028bd051-b2f1-4310-8f35-c41c9ce5a2f1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?812d3faa");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5003435 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31198");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-31195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange ProxyShell RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

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
    'cu' : 23,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.00.1497.18',
    'kb': '5003435'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 18,
    'cu' : 19,
    'min_version': '15.01.2176.0',
    'fixed_version': '15.01.2176.14',
    'kb': '5003435'
  },
  {
    'product': '2016',
    'unsupported_cu': 18,
    'cu' : 20,
    'min_version': '15.01.2242.0',
    'fixed_version': '15.01.2242.10',
    'kb': '5003435'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 7,
    'cu' : 8,
    'min_version': '15.02.792.0',
    'fixed_version': '15.02.792.15',
    'kb': '5003435'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 7,
    'cu' : 9,
    'min_version': '15.02.858.0',
    'fixed_version': '15.02.858.12',
    'kb': '5003435'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS21-05',
  constraints:constraints,
  severity:SECURITY_WARNING
);
