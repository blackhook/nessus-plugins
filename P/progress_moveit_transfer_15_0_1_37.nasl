#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176567);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2023-34362");
  script_xref(name:"CEA-ID", value:"CEA-2023-0018");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/23");

  script_name(english:"Progress MOVEit Transfer < 2020.0 / 2020.1 / 2021.0 < 2021.0.6 / 2021.1.0 < 2021.1.4 / 2022.0.0 < 2022.0.4 / 2022.1.0 < 2022.1.5 / 2023.0.0 < 2023.0.1 Critical Vulnerability (May 2023)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is prior to < 
2020.0 / 2020.1 / 2021.0 < 2021.0.6, 2021.1.4, 2022.0.4, 2022.1.5, or 2023.0.1. It is, therefore, affected by a SQL
injection vulnerability as referenced in Progress Community article 000234532.

  - A SQL injection vulnerability has been found in the MOVEit Transfer web
    application that could allow an un-authenticated attacker to gain
    unauthorized access to MOVEit Transfer's database. Depending on the database
    engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker
    may be able to infer information about the structure and contents of the
    database in addition to executing SQL statements that alter or delete
    database elements.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8b7c10b");
  # https://community.progress.com/s/article/Vulnerability-May-2023-Fix-for-MOVEit-Transfer-2020-1-12-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8493618");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2021.0.6, 2021.1.4, 2022.0.4, 2022.1.5, 2023.0.1, or later or apply the 
special patch for version 2020.1.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34362");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MOVEit SQL Injection vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
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
  { 'max_version': '12.1', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '12.1', 'fixed_version' : '12.1.8.13', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '13.0', 'fixed_version' : '13.0.6.49', 'fixed_display': '2021.0.6'},
  { 'min_version': '13.1', 'fixed_version' : '13.1.4.58', 'fixed_display': '2021.1.4'},
  { 'min_version': '14.0', 'fixed_version' : '14.0.4.43', 'fixed_display': '2022.0.4'},
  { 'min_version': '14.1', 'fixed_version' : '14.1.5.95', 'fixed_display': '2022.1.5'},
  { 'min_version': '15.0', 'fixed_version' : '15.0.1.37', 'fixed_display': '2023.0.1'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
