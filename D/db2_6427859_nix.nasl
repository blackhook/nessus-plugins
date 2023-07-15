##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147892);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id("CVE-2020-4976");
  script_xref(name:"IAVB", value:"2021-B-0019-S");

  script_name(english:"IBM DB2 9.7 < FP11 40690 / 10.1 < FP6 40689 / 10.5 < FP11 40688 / 11.1 < FP6 / 11.5 < FP1 File Read and Overwrite Vulnerability (UNIX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a file read and overwrite vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the remote host is either 9.7 prior to Fix Pack 11
Special Build 40690, 10.1 prior to Fix Pack 6 Special Build 40689, 10.5 prior to Fix Pack 11 Special Build 40688,
11.1 prior to Fix Pack 6 , or 11.5 prior to Fix Pack 1. It is, therefore, affected by a file permissions flaw related
to file handing that allows a local user to read and write specific files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6427859");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4976");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'equal':'9.7.0.11', 'fixed_build':'40690'},
  {'equal':'10.1.0.6', 'fixed_build':'40689'},
  {'equal':'10.5.0.11', 'fixed_build':'40688'},
  {'min_version':'9.7', 'fixed_version':'9.7.0.11', 'fixed_display':'9.7.0.11 + Special Build 40690'},
  {'min_version':'10.1', 'fixed_version':'10.1.0.6', 'fixed_display':'10.1.0.6 + Special Build 40689'},
  {'min_version':'10.5', 'fixed_version':'10.5.0.11', 'fixed_display':'10.5.0.11 + Special Build 40688'},
  {'min_version':'11.1', 'fixed_version':'11.1.4.6'},
  {'min_version':'11.5', 'fixed_version':'11.5.5.1'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);