#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143483);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id("CVE-2020-4701");
  script_xref(name:"IAVB", value:"2020-B-0068-S");

  script_name(english:"IBM DB2 10.5 < FP11 40479 / 11.1 < FP5 40478 / 11.5 < 11.5.5.0 Buffer Overflow (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"A buffer overflow condition exists in IBM DB2 due to improper bounds checking. An unauthenticated, local attacker can
exploit this to execute arbitrary code on the system with root privileges.
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6370025");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4701");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  {'equal':'10.5.0.11', 'fixed_build':'40479'},
  {'equal':'11.1.4.5', 'fixed_build':'40478'},
  {'min_version':'10.5', 'fixed_version':'10.5.0.11', 'fixed_display':'10.5.0.11 + Special Build 40479'},
  {'min_version':'11.1', 'fixed_version':'11.1.4.5', 'fixed_display':'11.1.4.5 + Special Build 40478'},
  {'min_version':'11.5', 'fixed_version':'11.5.5.0'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);