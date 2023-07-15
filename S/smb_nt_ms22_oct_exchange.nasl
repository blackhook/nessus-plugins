#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(166027);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id(
    "CVE-2022-21979",
    "CVE-2022-21980",
    "CVE-2022-24477",
    "CVE-2022-24516",
    "CVE-2022-30134",
    "CVE-2022-34692"
  );
  script_xref(name:"MSKB", value:"5019076");
  script_xref(name:"MSKB", value:"5019077");
  script_xref(name:"MSFT", value:"MS22-5019076");
  script_xref(name:"MSFT", value:"MS22-5019077");
  script_xref(name:"IAVA", value:"2022-A-0314-S");

  script_name(english:"Security Updates for Exchange (October 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive information.
    (CVE-2022-21979,CVE-2022-30134, CVE-2022-34692)

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. (CVE-2022-21980,
    CVE-2022-24477, CVE-2022-24516)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5019076");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5019077");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
-KB5019076
-KB5019077");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'fixed_version': '15.0.1497.42',
    'kb': '5019076'
  },
  {
    'product' : '2016',
    'cu': 22,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2375.32',
    'kb': '5019077'
  },
  {
    'product': '2016',
    'cu': 23,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2507.13',
    'kb': '5019077'
  },
  {
    'product' : '2019',
    'cu': 11,
    'unsupported_cu': 10,
    'fixed_version': '15.2.986.30',
    'kb': '5019077'
  },
  {
    'product' : '2019',
    'cu': 12,
    'unsupported_cu': 10,
    'fixed_version': '15.2.1118.15',
    'kb': '5019077'
  }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS22-10',
  constraints:constraints,
  severity:SECURITY_HOLE
);
