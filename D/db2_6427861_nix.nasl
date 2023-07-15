#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(147890);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id("CVE-2020-5024", "CVE-2020-5025");
  script_xref(name:"IAVB", value:"2021-B-0019-S");

  script_name(english:"IBM DB2 9.7 < 9.7 FP11 40690 / 10.1 < 10.1 FP6 40689 / 10.5 < 10.5 FP11 40688 / 11.1 < 11.1.4 FP6 / 11.5 < 11.5.5 FP0 6195 Multiple Vulnerabilities (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, IBM Db2 is affected by multiple vulnerabilities:

  - IBM Db2 for Linux, UNIX and Windows could allow an unauthenticated attacker to cause a denial of service due to a
    hang in the SSL handshake response. (CVE-2020-5024)

  - IBM Db2 db2fm is vulnerable to a buffer overflow, caused by improper bounds checking which could allow a local
    attacker to execute arbitrary code on the system with root privileges. (CVE-2020-5025)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6427861");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6427855");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5025");

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

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'equal':'11.5.5.0', 'fixed_build':'6195'},
  {'min_version':'9.7', 'fixed_version':'9.7.0.11', 'fixed_display':'9.7.0.11 + Special Build 40690'},
  {'min_version':'10.1', 'fixed_version':'10.1.0.6', 'fixed_display':'10.1.0.6 + Special Build 40689'},
  {'min_version':'10.5', 'fixed_version':'10.5.0.11', 'fixed_display':'10.5.0.11 + Special Build 40688'},
  {'min_version':'11.1', 'fixed_version':'11.1.4.6'},
  {'min_version':'11.5', 'fixed_version':'11.5.5.0', 'fixed_display':'11.5.5.0 + Special Build 6195'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
