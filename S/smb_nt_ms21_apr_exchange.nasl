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
  script_id(148476);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/20");

  script_cve_id(
    "CVE-2021-28480",
    "CVE-2021-28481",
    "CVE-2021-28482",
    "CVE-2021-28483",
    "CVE-2021-33766",
    "CVE-2021-34473",
    "CVE-2021-34523"
  );
  script_xref(name:"MSKB", value:"5001779");
  script_xref(name:"MSFT", value:"MS21-5001779");
  script_xref(name:"IAVA", value:"2021-A-0160-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/01");
  script_xref(name:"CEA-ID", value:"CEA-2021-0040");
  script_xref(name:"CEA-ID", value:"CEA-2021-0022");
  script_xref(name:"CEA-ID", value:"CEA-2021-0021");

  script_name(english:"Security Updates for Microsoft Exchange Server (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker could exploit this to
    execute unauthorized arbitrary code. (CVE-2021-28483, CVE-2021-28482,
    CVE-2021-28481, CVE-2021-28480, CVE-2021-34473)

  - An elevation of privilege vulnerability. An attacker can exploit this to
  gain elevated privileges. (CVE-2021-34523)

  - An information disclosure vulnerability. An attacker can exploit this to
  disclose potentially sensitive information. (CVE-2021-33766)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-april-13-2021-kb5001779-8e08f3b3-fc7b-466c-bbb7-5d5aa16ef064
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bdeeea7");
  # https://msrc-blog.microsoft.com/2021/04/13/april-2021-update-tuesday-packages-now-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b66291c9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5001779");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34473");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-34523");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange ProxyShell RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

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
    'kb': '5001779'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 18,
    'cu' : 20,
    'min_version': '15.01.2176.0',
    'fixed_version': '15.01.2176.14',
    'kb': '5001779'
  },
  {
    'product': '2016',
    'unsupported_cu': 18,
    'cu' : 20,
    'min_version': '15.01.2242.0',
    'fixed_version': '15.01.2242.10',
    'kb': '5001779'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 7,
    'cu' : 8,
    'min_version': '15.02.792.0',
    'fixed_version': '15.02.792.15',
    'kb': '5001779'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 7,
    'cu' : 9,
    'min_version': '15.02.858.0',
    'fixed_version': '15.02.858.12',
    'kb': '5001779'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS21-05',
  constraints:constraints,
  severity:SECURITY_WARNING
);