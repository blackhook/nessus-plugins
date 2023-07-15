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
  script_id(154175);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-26427",
    "CVE-2021-34453",
    "CVE-2021-41348",
    "CVE-2021-41350"
  );
  script_xref(name:"MSKB", value:"5007011");
  script_xref(name:"MSKB", value:"5007012");
  script_xref(name:"MSFT", value:"MS21-5007011");
  script_xref(name:"MSFT", value:"MS21-5007012");
  script_xref(name:"IAVA", value:"2021-A-0466-S");

  script_name(english:"Security Updates for Exchange (October 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute 
    unauthorized arbitrary commands. (CVE-2021-26427)
  
  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. (CVE-2021-41348)
  
  - A session spoofing vulnerability exists. An attacker can exploit this to perform actions with the privileges of 
    another user. (CVE-2021-41350)

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected component to deny
    system or application services. (CVE-2021-34453)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5007011");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5007012");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5007011
  -KB5007012");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26427");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'fixed_version': '15.0.1497.024',
    'kb': '5007011'
  },
  {
    'product' : '2016', 
    'unsupported_cu' : 19, 
    'min_version': '15.1.2308.0', 
    'fixed_version': '15.1.2308.15',
    'kb': '5007012'
  },
  {
    'product': '2016',
    'unsupported_cu': 19,
    'min_version': '15.1.2375.0',
    'fixed_version': '15.1.2375.12',
    'kb': '5007012'
  },
  {
    'product' : '2019', 
    'unsupported_cu' : 8,
    'min_version': '15.2.922.0',
    'fixed_version': '15.2.922.14',
    'kb': '5007012'
  },
  {
    'product' : '2019', 
    'unsupported_cu' : 8,
    'min_version': '15.2.986.0',
    'fixed_version': '15.2.986.9',
    'kb': '5007012'
  }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info, 
  bulletin:'MS21-10',
  constraints:constraints, 
  severity:SECURITY_WARNING
);
