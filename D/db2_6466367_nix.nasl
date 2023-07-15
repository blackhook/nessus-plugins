#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151352);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id("CVE-2020-4885", "CVE-2020-4945");
  script_xref(name:"IAVB", value:"2021-B-0038");

  script_name(english:"IBM DB2 11.5 < 11.5.6 FP0 Multiple Vulnerabilities (UNIX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the remote host is 11.5 prior to 11.5.6 FP0. It is,
therefore, affected by multiple vulnerabilities including the following:
  
  - IBM DB2 is affected by a flaw which could allow an unauthenticated, local user to to access and change 
  configuration of the database. This is due to a race condition of a symbolic link. (CVE-2020-4885)

  - An arbitrary file write vulnerability exists in IBM DB2 due to improper group permissions. An 
  authenticated, remote attacker can exploit this to write arbitrary files on the remote host.
  (CVE-2020-4945)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.ibm.com/support/pages/published-security-vulnerabilities-db2-linux-unix-and-windows-including-special-build-information
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd7b2203");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6466363");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6466367");
  script_set_attribute(attribute:"solution", value:
"Update IBM DB2 version to 11.5.6 FP0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

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
  {'min_version':'11.5', 'fixed_version':'11.5.6'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);