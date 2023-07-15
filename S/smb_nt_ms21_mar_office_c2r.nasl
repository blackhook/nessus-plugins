#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(161755);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2021-24108", "CVE-2021-27058");
  script_xref(name:"IAVA", value:"2021-A-0132-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Security Updates for Microsoft Office Products C2R (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
They are affected by a remote code execution vulnerability. An attacker can exploit this to bypass 
authentication and execute unauthorized arbitrary commands. (CVE-2021-24108, CVE-2021-27058)");
  # https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#march-09-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b73190a");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27058");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS21-03';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  {'product' : 'Microsoft Office 2016', 'channel':'Deferred', 'channel_version':'2008', 'file':'graph.exe', 'fixed_version': '16.0.13127.21348'},
  {'product' : 'Microsoft Office 2016', 'channel':'Microsoft 365 Apps on Windows 7', 'file':'graph.exe', 'fixed_version': '16.0.12527.21686'},
  {'product' : 'Microsoft Office 2016', 'channel':'Deferred', 'file':'graph.exe', 'fixed_version': '16.0.12527.21686'},
  {'product' : 'Microsoft Office 2016', 'channel':'Enterprise Deferred', 'channel_version':'2101', 'file':'graph.exe', 'fixed_version': '16.0.13628.20528'},
  {'product' : 'Microsoft Office 2016', 'channel':'Enterprise Deferred', 'file':'graph.exe', 'fixed_version': '16.0.13530.20628'},
  {'product' : 'Microsoft Office 2016', 'channel':'First Release for Deferred', 'file':'graph.exe', 'fixed_version': '16.0.13801.20294'},
  {'product' : 'Microsoft Office 2016', 'channel':'2016 Retail', 'file':'graph.exe', 'fixed_version': '16.0.13801.20294'},
  {'product' : 'Microsoft Office 2016', 'channel':'Current', 'file':'graph.exe', 'fixed_version': '16.0.13801.20294'},
  {'product' : 'Microsoft Office 2019', 'channel':'2019 Volume', 'file':'graph.exe', 'fixed_version': '16.0.10372.20060'},
  {'product' : 'Microsoft Office 2019', 'channel':'2019 Retail', 'file':'graph.exe', 'fixed_version': '16.0.13801.20294'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Excel'
);

