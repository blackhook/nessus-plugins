#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177082);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/17");

  script_cve_id("CVE-2023-35036");
  script_xref(name:"CEA-ID", value:"CEA-2023-0019");
  script_xref(name:"CEA-ID", value:"CEA-2023-0023");

  script_name(english:"Progress MOVEit Transfer < 2020.1.9 / 2021.0.x < 2021.0.7 / 2021.1.x < 2021.1.5 / 2022.0.x < 2022.0.5 / 2022.1.x < 2022.1.6 / 2023.0.x < 2023.0.2 Critical Vulnerability (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Progress MOVEit Transfer, formerly Ipswitch MOVEit DMZ, installed on the remote host is prior to
2020.1.9, 2021.0.7, 2021.1.5, 2022.0.5, 2022.1.6, or 2023.0.2. It is, therefore, affected by a SQL injection
vulnerability as referenced in Progress Community article 000234899.

  - Multiple SQL injection vulnerabilities have been identified in the MOVEit Transfer web application that could allow
    an un-authenticated attacker to gain unauthorized access to the MOVEit Transfer database. An attacker could submit a
    crafted payload to a MOVEit Transfer application endpoint which could result in modification and disclosure of
    MOVEit database content.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-CVE-Pending-Reserve-Status-June-9-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95b1e6ea");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2020.1.9, 2021.0.7, 2021.1.5, 2022.0.5, 2022.1.6, 2023.0.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/09");

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

var dll_ver = app_info['MOVEit.DMZ.ClassLib.dll version'];
if (!empty_or_null(object: dll_ver))
{
  app_info.version = dll_ver;
  app_info.parsed_version = vcf::parse_version(dll_ver);
}

var constraints = [
  { 'max_version': '12.1', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '12.1', 'fixed_version' : '12.1.9.15', 'fixed_display': '2020.1.9'},
  { 'min_version': '13.0', 'fixed_version' : '13.0.7.51', 'fixed_display': '2021.0.7'},
  { 'min_version': '13.1', 'fixed_version' : '13.1.5.60', 'fixed_display': '2021.1.5'},
  { 'min_version': '14.0', 'fixed_version' : '14.0.5.45', 'fixed_display': '2022.0.5'},
  { 'min_version': '14.1', 'fixed_version' : '14.1.6.97', 'fixed_display': '2022.1.6'},
  { 'min_version': '15.0', 'fixed_version' : '15.0.2.39', 'fixed_display': '2023.0.2'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
