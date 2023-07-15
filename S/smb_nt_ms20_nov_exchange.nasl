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
  script_id(142888);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085");
  script_xref(name:"MSKB", value:"4588741");
  script_xref(name:"MSFT", value:"MS20-4588741");
  script_xref(name:"IAVA", value:"2020-A-0515-S");

  script_name(english:"Security Updates for Exchange (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - Unspecified flaws exist that allow an attacker to
    execute arbitrary code. (CVE-2020-17083, CVE-2020-17084)
  
  - An unspecified flaw exists that allows an attacker to
    cause denial of service conditions. (CVE-2020-17085)
    
Please review the vendor advisory for more details.");
  # https://support.microsoft.com/en-us/help/4588741/description-of-the-security-update-for-microsoft-exchange-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?226ec4af");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4588741 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17084");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'fixed_version': '15.00.1497.8',
    'kb': '4588741'
  },
  {
    'product': '2016',
    'unsupported_cu': 16,
    'cu' : 17,
    'min_version': '15.01.2044.0',
    'fixed_version': '15.01.2044.8',
    'kb': '4588741'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 16,
    'cu' : 18,
    'min_version': '15.01.2106.0',
    'fixed_version': '15.01.2106.4',
    'kb': '4588741'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 5,
    'cu' : 6,
    'min_version': '15.02.659.0',
    'fixed_version': '15.02.659.8',
    'kb': '4588741'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 5,
    'cu' : 7,
    'min_version': '15.02.721.0',
    'fixed_version': '15.02.721.4',
    'kb': '4588741'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS20-11',
  constraints:constraints,
  severity:SECURITY_WARNING
);