#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101161);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id("CVE-2017-1105", "CVE-2017-1297");
  script_bugtraq_id(99264, 99271);

  script_name(english:"IBM DB2 9.7 < FP11 Special Build 36621 / 10.1 < FP6 Special Build 36610 / 10.5 < FP8 Special Build 36605 / 11.1.2 < FP2 Multiple Vulnerabilities (UNIX)");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is either 9.7 prior to Fix Pack 11 Special Build 36621,
10.1 prior to Fix Pack 6 Special Build 36610, 10.5 prior to Fix Pack 8
Special Build 36605, or 11.1.2 prior to Fix Pack 2. It is, therefore,
affected by the following vulnerabilities :

  - A buffer overflow condition exists due to improper
    validation of user-supplied input. A local attacker can
    exploit this to overwrite DB2 files or cause a denial of
    service condition. (CVE-2017-1105)

  - A stack-based buffer overflow condition exists in the
    Command Line Process (CLP) due to improper bounds
    checking. A local attacker can exploit this to execute
    arbitrary code. (CVE-2017-1297)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22003877");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22004878");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the
most recent fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1297");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");
  script_exclude_keys("SMB/db2/Installed");

  exit(0);
}

include('vcf_extras_db2.inc');

# The remote host's OS is Windows, not Linux.
if (get_kb_item('SMB/db2/Installed'))
  audit(AUDIT_OS_NOT, 'Linux', 'Windows');

var app_info = vcf::ibm_db2::get_app_info();
# DB2 has an optional OpenSSH server that will run on
# windows.  We need to exit out if we picked up the windows
# installation that way.
if ('Windows' >< app_info['platform'])
  audit(AUDIT_HOST_NOT, 'a Linux based operating system');

var constraints = [
  {'equal':'9.7.0.11', 'fixed_build':'36621'},
  {'equal':'10.1.0.6', 'fixed_build':'36610'},
  {'equal':'10.5.0.8', 'fixed_build':'36605'},
  {'min_version':'9.7', 'fixed_version':'9.7.0.11', 'fixed_display':'9.7.0.11 + Special Build 36621'},
  {'min_version':'10.1', 'fixed_version':'10.1.0.6', 'fixed_display':'10.1.0.6 + Special Build 36610'},
  {'min_version':'10.5', 'fixed_version':'10.5.0.8', 'fixed_display':'10.5.0.8 + Special Build 36605'},
  {'min_version':'11.1', 'fixed_version':'11.1.2.2'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);