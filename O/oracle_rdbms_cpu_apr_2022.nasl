#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160079);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2021-22569",
    "CVE-2021-41164",
    "CVE-2021-41165",
    "CVE-2022-21410",
    "CVE-2022-21411",
    "CVE-2022-21498"
  );
  script_xref(name:"IAVA", value:"2022-A-0164");

  script_name(english:"Oracle Database Server (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2022 CPU advisory.

  - Vulnerability in the Oracle Database - Enterprise Edition Sharding component of Oracle Database Server.
    The supported version that is affected is 19c. Easily exploitable vulnerability allows high privileged
    attacker having Create Any Procedure privilege with network access via Oracle Net to compromise Oracle
    Database - Enterprise Edition Sharding. Successful attacks of this vulnerability can result in takeover of
    Oracle Database - Enterprise Edition Sharding. (CVE-2022-21410)

  - Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected are
    12.1.0.2, 19c and 21c. Easily exploitable vulnerability allows low privileged attacker having Create
    Procedure privilege with network access via multiple protocols to compromise Java VM. Successful attacks
    of this vulnerability can result in unauthorized creation, deletion or modification access to critical
    data or all Java VM accessible data. (CVE-2022-21498)

  - Vulnerability in the RDBMS Gateway / Generic ODBC Connectivity component of Oracle Database Server.
    Supported versions that are affected are 12.1.0.2, 19c and 21c. Easily exploitable vulnerability allows
    low privileged attacker having Create Session privilege with network access via Oracle Net to compromise
    RDBMS Gateway / Generic ODBC Connectivity. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of RDBMS Gateway / Generic ODBC Connectivity
    accessible data as well as unauthorized read access to a subset of RDBMS Gateway / Generic ODBC
    Connectivity accessible data. (CVE-2022-21411)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21410");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  # Note there are no Combo or OJVM patches for 21.x. OJVM fixes are released as part of the RU patches.
  # See note next to 21.x patches for Jan 22'
  {'min_version': '21.0', 'fixed_version': '21.6.0.0.220419', 'missing_patch':'33843745', 'os':'unix', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.6.0.0.220419', 'missing_patch':'33829143', 'os':'win', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.13.2.0.220419', 'missing_patch':'33783771', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.15.0.0.220419', 'missing_patch':'33829175', 'os':'win', 'component':'db'},
  {'min_version': '19.14', 'fixed_version': '19.14.1.0.220419', 'missing_patch':'33806138', 'os':'unix', 'component':'db'},
  {'min_version': '19.15', 'fixed_version': '19.15.0.0.220419', 'missing_patch':'33806152', 'os':'unix', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.220419', 'missing_patch':'33711072, 33711081', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.220419', 'missing_patch':'33777450', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.15.0.0.220419', 'missing_patch':'33808367', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.15.0.0.220419', 'missing_patch':'33808367', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.220419', 'missing_patch':'33808385', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.220419', 'missing_patch':'33881387', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
