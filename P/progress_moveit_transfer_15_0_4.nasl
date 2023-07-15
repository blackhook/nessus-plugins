#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(178016);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-36932", "CVE-2023-36933", "CVE-2023-36934");
  script_xref(name:"IAVA", value:"2023-A-0333");

  script_name(english:"Progress MOVEit Transfer < 2020.1.11 / 2021.0 < 2021.0.9 / 2021.1 < 2021.1.7 / 2022.0 < 2022.0.7, 2022.1 < 2022.1.8 / 2023.0 < 2023.0.4 Multiple Vulnerabilities (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is prior to
2020.1.11 / 2021.0 < 2021.0.9 / 2021.1 < 2021.1.7 / 2022.0 < 2022.0.7, 2022.1 < 2022.1.8 / 2023.0 < 2023.0.4. It is,
therefore, affected by multiple vulnerabilities as referenced in Progress Community article 000236387.

  - In Progress MOVEit Transfer before 2020.1.11 (12.1.11), 2021.0.9 (13.0.9), 2021.1.7 (13.1.7), 2022.0.7
  (14.0.7), 2022.1.8 (14.1.8), and 2023.0.4 (15.0.4), multiple SQL injection vulnerabilities have been
  identified in the MOVEit Transfer web application that could allow an authenticated attacker to gain
  unauthorized access to the MOVEit Transfer database. An attacker could submit a crafted payload to a
  MOVEit Transfer application endpoint that could result in modification and disclosure of MOVEit database
  content. (CVE-2023-36932)

  - In Progress MOVEit Transfer before 2021.0.9 (13.0.9), 2021.1.7 (13.1.7), 2022.0.7 (14.0.7), 2022.1.8
  (14.1.8), and 2023.0.4 (15.0.4), it is possible for an attacker to invoke a method that results in an
  unhandled exception. Triggering this workflow can cause the MOVEit Transfer application to terminate
  unexpectedly. (CVE-2023-36933)

  - In Progress MOVEit Transfer before 2020.1.11 (12.1.11), 2021.0.9 (13.0.9), 2021.1.7 (13.1.7), 2022.0.7
  (14.0.7), 2022.1.8 (14.1.8), and 2023.0.4 (15.0.4), a SQL injection vulnerability has been identified in
  the MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized
  access to the MOVEit Transfer database. An attacker could submit a crafted payload to a MOVEit Transfer
  application endpoint that could result in modification and disclosure of MOVEit database content.
  (CVE-2023-36934)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-2020-1-Service-Pack-July-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23d797a5");
  # https://community.progress.com/s/article/MOVEit-Transfer-Service-Pack-July-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff010ca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2020.1.11, 2021.0.9, 2021.1.7, 2022.0.7, 2022.1.8, 2023.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ipswitch_dmz_ftp_installed.nbin");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('install_func.inc');
include('smb_func.inc');

var appname = 'Ipswitch MOVEit DMZ';
var app_info = vcf::get_app_info(app:appname);

# Special patch for 2020.1x/12.1.x involves copying several dlls
var dll_ver = app_info["MOVEit.DMZ.Application.dll version"];
if (app_info.version =~ "^12\.1" && !empty_or_null(object: dll_ver))
{
  app_info.version = dll_ver;
  app_info.parsed_version = vcf::parse_version(dll_ver);
}

var constraints = [
  { 'max_version': '12.0.99999999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '12.1', 'fixed_version' : '12.1.11.19', 'fixed_display': '2020.1.11 (12.1.11)'},
  { 'min_version': '13.0', 'fixed_version' : '13.0.9.58', 'fixed_display': '2021.0.9 (13.0.9)'},
  { 'min_version': '13.1', 'fixed_version' : '13.1.7.68', 'fixed_display': '2021.1.7 (13.1.7)'},
  { 'min_version': '14.0', 'fixed_version' : '14.0.7.54', 'fixed_display': '2022.0.7 (14.0.7)'},
  { 'min_version': '14.1', 'fixed_version' : '14.1.8.106', 'fixed_display': '2022.1.7 (14.1.8)'},
  { 'min_version': '15.0', 'fixed_version' : '15.0.4.49', 'fixed_display': '2023.0.4 (15.0.4)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
