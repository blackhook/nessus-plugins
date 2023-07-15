#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(162055);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2021-34478", "CVE-2021-36941");
  script_xref(name:"IAVA", value:"2021-A-0376-S");

  script_name(english:"Security Updates for Microsoft Office Products C2R (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple remote code
execution vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS21-08';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13801.20864','channel': 'Deferred','channel_version': '2102'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13127.21736','channel': 'Deferred','channel_version': '2008'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12527.22017','channel': 'Microsoft 365 Apps on Windows 7'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12527.22017','channel': 'Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14131.20360','channel': 'Enterprise Deferred','channel_version': '2106'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14026.20352','channel': 'Enterprise Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13801.20864','channel': 'First Release for Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14228.20250','channel': '2016 Retail'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14228.20250','channel': 'Current'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.14228.20250','channel': '2019 Retail'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10377.20023','channel': '2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Office'
);