#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173398);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2023-27532");
  script_xref(name:"IAVA", value:"2023-A-0233");

  script_name(english:"Veeam Backup and Replication Authentication Bypass (KB4288)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is affected by an authentication
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is prior to 11.0.1.1261
P20230227 or 12.x prior to 12.0.0.1420 P20230223. It is, therefore, affected by authentication bypass vulnerability that
allows encrypted credentials stored in the configuration database to be obtained. This may lead to gaining access to the
backup infrastructure hosts.

Note that Nessus has not tested for this issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4424");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Backup and Replication version 11.0.1.1261 P20230227 or 12.0.0.1420 P20230223 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27532");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:backup_and_replication");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veeam_backup_and_replication_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Veeam Backup and Replication");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Veeam Backup and Replication', win_local:TRUE);

var version = app_info['version'];
var patch_level = app_info['Patch'];

if (empty_or_null(patch_level))
  patch_level = '0';

var fix = NULL;

# anything < 11.0.1.1261
# 11.0.1.1261 < P20230227
if (ver_compare(ver:version, fix:'11.0.1.1261', strict:FALSE) < 0 ||
   (version == '11.0.1.1261' && (ver_compare(ver:patch_level, fix:'20230227', strict:FALSE) < 0)))
{
  fix = '11.0.1.1261 P20230227';
}

# 12.0.x < 12.0.0.1420
# 12.0.0.1420 < P20230223
if (version =~ "^12\.0\.")
{
  if (ver_compare(ver:version, fix:'12.0.0.1420', strict:FALSE) < 0 ||
      (version == '12.0.0.1420' && (ver_compare(ver:patch_level, fix:'20230223', strict:FALSE) < 0)))
  {
    fix = '12.0.0.1420 P20230223';
  }
}

if (!isnull(fix))
{
  vcf::report_results(app_info:app_info, fix:fix, severity:SECURITY_HOLE);
}
else
{
  vcf::audit(app_info);
}
