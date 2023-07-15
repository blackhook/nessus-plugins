#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91335);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id(
    "CVE-2016-0211",
    "CVE-2016-0215"
  );

  script_name(english:"IBM DB2 9.7 < FP11 Special Build 35317 / 10.1 < FP5 Special Build 35316 / 10.5 < FP7 Special Build 35315 Multiple Vulnerabilities (UNIX)");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is either 9.7 prior to fix pack 11 Special Build 35317,
10.1 prior to fix pack 5 Special Build 35316, or 10.5 prior to fix
pack 7 Special Build 35315. It is, therefore, affected by the
following vulnerabilities :

  - A denial of service vulnerability exists in LUW related
    to the handling of DRDA messages. An authenticated,
    remote attacker can exploit this, via a specially
    crafted DRDA message, to cause the DB2 server to
    terminate abnormally. (CVE-2016-0211)

  - A denial of service vulnerability exists in LUW when
    handling SELECT statements with subqueries containing
    the AVG OLAP function that are applied to Oracle
    compatible databases. An authenticated, remote attacker
    can exploit this, via a specially crafted query, to
    cause the DB2 server to terminate abnormally.
    (CVE-2016-0215)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979984");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979986");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Special Build based on the most recent
fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0215");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
   {'equal':'9.7.0.11', 'fixed_build':'35317'},
   {'equal':'10.1.0.5', 'fixed_build':'35316'},
   {'equal':'10.5.0.7', 'fixed_build':'35315'},
   {'min_version':'9.7', 'fixed_version':'9.7.0.11', 'fixed_display':'9.7.0.11 + Special Build 35317'},
   {'min_version':'10.1', 'fixed_version':'10.1.0.5', 'fixed_display':'10.1.0.5 + Special Build 35316'},
   {'min_version':'10.5', 'fixed_version':'10.5.0.7', 'fixed_display':'10.5.0.7 + Special Build 35315'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
