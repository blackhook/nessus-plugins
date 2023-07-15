#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151664);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-31196",
    "CVE-2021-31206",
    "CVE-2021-33768",
    "CVE-2021-34470"
  );
  script_xref(name:"MSKB", value:"5003611");
  script_xref(name:"MSKB", value:"5003612");
  script_xref(name:"MSKB", value:"5004778");
  script_xref(name:"MSKB", value:"5004779");
  script_xref(name:"MSKB", value:"5004780");
  script_xref(name:"MSFT", value:"MS21-5003611");
  script_xref(name:"MSFT", value:"MS21-5003612");
  script_xref(name:"MSFT", value:"MS21-5004778");
  script_xref(name:"MSFT", value:"MS21-5004779");
  script_xref(name:"MSFT", value:"MS21-5004780");
  script_xref(name:"IAVA", value:"2021-A-0315-S");

  script_name(english:"Security Updates for Exchange (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security
updates. It is, therefore, affected by multiple vulnerabilities:

- A remote code execution vulnerability. An attacker can exploit this to bypass
  authentication and execute unauthorized arbitrary commands.  (CVE-2021-31196,
  CVE-2021-31206)

- An elevation of privilege vulnerability. An attacker can exploit this to gain
  elevated privileges. (CVE-2021-33768, CVE-2021-34470)

Note: Nessus is unable to determine if the latest Active Directory schema has
been applied.");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2016-july-13-2021-kb5004779-81e40da3-60db-4c09-bf11-b8c1e0c1b77d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a44a0d8a");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-july-13-2021-kb5004780-fc5b3fa1-1f7a-47b0-8014-699257256bb5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f529b54");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2013-july-13-2021-kb5004778-f532100d-a9c1-4f2c-bc36-baec95881011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecec1115");
  # https://support.microsoft.com/en-us/topic/cumulative-update-21-for-exchange-server-2016-kb5003611-b7ba1656-abba-4a0b-9be9-dac45095d969
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51a55048");
  # https://support.microsoft.com/en-us/topic/cumulative-update-10-for-exchange-server-2019-kb5003612-b1434cad-3fbc-4dc3-844d-82568e8d4344
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c76ecd10");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following KBs to address these issues:
 - KB5003611
 - KB5003612
 - KB5004778
 - KB5004779
 - KB5004780");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31206");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-34470");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

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
    'cu' : 23,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.0.1497.23'
  },
  {
    'product': '2016',
    'unsupported_cu': 19,
    'cu' : 20,
    'min_version': '15.01.2242.0',
    'fixed_version': '15.01.2242.12'
  },
  {
     'product' : '2016',
     'unsupported_cu' : 19,
     'cu' : 21,
     'min_version': '15.01.2308.0',
     'fixed_version': '15.01.2308.14'
   },
  {
     'product' : '2019',
     'unsupported_cu' : 8,
     'cu' : 9,
     'min_version': '15.02.858.0',
     'fixed_version': '15.02.858.15'
   },
  {
    'product' : '2019',
    'unsupported_cu' : 8,
    'cu' : 10,
    'min_version': '15.02.922.0',
    'fixed_version': '15.02.922.13'
  }

];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS21-07',
  constraints:constraints,
  severity:SECURITY_WARNING
);