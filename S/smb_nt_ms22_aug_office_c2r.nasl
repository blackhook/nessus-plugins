##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164043);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/20");

  script_cve_id("CVE-2022-34717");
  script_xref(name:"IAVA", value:"2022-A-0316-S");
  script_xref(name:"IAVA", value:"2022-A-0317-S");
  script_xref(name:"IAVA", value:"2022-A-0325-S");

  script_name(english:"Security Updates for Microsoft Office Products C2R RCE (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by a remote code 
execution vulnerability. An attacker can exploit this to bypass authentication and execute unauthorized 
arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4462148");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4462142");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-08';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15427.20210','channel':'2016 Retail'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15427.20210','channel':'Current'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15330.20298','channel':'Enterprise Deferred','channel_version':'2206'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15225.20394','channel':'Enterprise Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14931.20660','channel':'First Release for Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14931.20660','channel':'Deferred','channel_version':'2202'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14326.21096','channel':'Deferred','channel_version':'2108'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13801.21582','channel':'Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12527.22197','channel':'Microsoft 365 Apps on Windows 7'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.15427.20210','channel':'2021 Retail'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.15427.20210','channel':'2019 Retail'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.14332.20358','channel':'LTSC 2021'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10389.20033','channel':'2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Office'
);

