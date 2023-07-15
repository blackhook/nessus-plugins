#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177371);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-35708");
  script_xref(name:"CEA-ID", value:"CEA-2023-0023");
  script_xref(name:"IAVA", value:"2023-A-0314-S");

  script_name(english:"Progress MOVEit Transfer < 2020.1.10 / 2021.0.x < 2021.0.8 / 2021.1.x < 2021.1.6 / 2022.0.x < 2022.0.6 / 2022.1.x < 2022.1.7 / 2023.0.x < 2023.0.3 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"Progress MOVEit Transfer has a privilege escalation vulnerability that can be addressed with DLL drop-in version
2023.0.3 (15.0.3) and other specific fixed versions (stated below). The availability date of fixed versions of the
DLL drop-in is earlier than the availability date of fixed versions of the full installer. The specific weakness
and impact details will be mentioned in a later update to this CVE Record. These are fixed versions of the DLL
drop-in: 2020.1.10 (12.1.10), 2021.0.8 (13.0.8), 2021.1.6 (13.1.6), 2022.0.6 (14.0.6), 2022.1.7 (14.1.7), and
2023.0.3 (15.0.3).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-15June2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?601c5784");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress MOVEit Transfer version 2020.1.10, 2021.0.8, 2021.1.6, 2022.0.6, 2022.1.7, 2023.0.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_dmz_ftp_installed.nbin");
  script_require_keys("installed_sw/Ipswitch MOVEit DMZ", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var appname = 'Ipswitch MOVEit DMZ';
var app_info = vcf::get_app_info(app:appname, win_local:TRUE);

var dll_ver = app_info['MOVEit.DMZ.ClassLib.dll version'];
if (!empty_or_null(object: dll_ver))
{
  app_info.version = dll_ver;
  app_info.parsed_version = vcf::parse_version(dll_ver);
}

var constraints = [
  { 'max_version': '12.0.99999999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '12.1', 'fixed_version' : '12.1.10', 'fixed_display': '2020.1.10 (12.1.10)'},
  { 'min_version': '13.0', 'fixed_version' : '13.0.8', 'fixed_display': '2021.0.8 (13.0.8)'},
  { 'min_version': '13.1', 'fixed_version' : '13.1.6', 'fixed_display': '2021.1.6 (13.1.6)'},
  { 'min_version': '14.0', 'fixed_version' : '14.0.6', 'fixed_display': '2022.0.6 (14.0.6)'},
  { 'min_version': '14.1', 'fixed_version' : '14.1.7', 'fixed_display': '2022.1.7 (14.1.7)'},
  { 'min_version': '15.0', 'fixed_version' : '15.0.3', 'fixed_display': '2023.0.3 (15.0.3)'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
