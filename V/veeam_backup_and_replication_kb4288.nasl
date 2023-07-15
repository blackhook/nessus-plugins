#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168945);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id("CVE-2022-26500", "CVE-2022-26501");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/03");

  script_name(english:"Veeam Backup and Replication Multiple Vulnerabilities (KB4288)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is a version prior to 10.0.1.4854
P20220304 or prior to 11.0.1.1261 P20220302 or prior to. It is, therefore, affected by multiple vulnerabilities:

  - Improper limitation of path names in Veeam Backup & Replication 9.5U3, 9.5U4,10.x, and 11.x allows remote
    authenticated users access to internal API functions that allows attackers to upload and execute arbitrary code.
    (CVE-2022-26500)

  - Veeam Backup & Replication 10.x and 11.x has Incorrect Access Control. (CVE-2022-26501)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4288");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Backup & Replication version 10.0.1.4854 P20220304 / 11.0.1.1261 P20220302 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26501");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:backup_and_replication");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# 9.5.x
# 10.0.x < 10.0.1.4854
# 10.0.1.4854 < P20220304
if (version =~ "^9\.5\." || version =~ "^10\.0\.")
{
  if (ver_compare(ver:version, fix:'10.0.1.4854', strict:FALSE) < 0 ||
      (version == '10.0.1.4854' && (ver_compare(ver:patch_level, fix:'20220304', strict:FALSE) < 0)))
  {
    fix = '10.0.1.4854 P20220304';
  }
}

# 11.0.x < 11.0.1.1261
# 11.0.1.1261 < P20220302
if (version =~ "^11\.0\.")
{
  if (ver_compare(ver:version, fix:'11.0.1.1261', strict:FALSE) < 0 ||
      (version == '11.0.1.1261' && (ver_compare(ver:patch_level, fix:'20220302', strict:FALSE) < 0)))
  {
    fix = '11.0.1.1261 P20220302';
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
