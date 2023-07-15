#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111219);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-15095",
    "CVE-2018-2939",
    "CVE-2018-3004",
    "CVE-2018-3110"
  );
  script_bugtraq_id(103880);

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (July 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the July 2018 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities:

  - An unspecified vulnerability in the Oracle Spatial
    (jackson-databind) component of Oracle Database Server
    allows an unauthenticated, remote attacker with network
    access via multiple protocols to compromise Oracle
    Spatial. (CVE-2017-15095)

  - An unspecified vulnerability in the Core RDBMS
    component of Oracle Database Server allows a low
    privileged attacker to inject or manipulate RDBMS data,
    resulting in compromise of Core RDBMS. (CVE-2018-2939)

  - An unspecified vulnerability in the Java VM component
    of Oracle Database Server allows a low privileged
    attacker with Create Session, Create Procedure privilege
    to compromise a Java VM. (CVE-2018-3004, CVE-2018-3110)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f36723");
  # https://www.oracle.com/technetwork/security-advisory/alert-cve-2018-3110-5032149.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f4d652e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '18.3', 'fixed_version': '18.3.0.0.180717', 'missing_patch':'28317326, 28090523', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.2.1.0.180717', 'missing_patch':'28346593, 28601267, 28702032', 'os':'unix', 'component':'db'},
  
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.180717', 'missing_patch':'28317292, 28163133, 28662603, 28672345, 28714316', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.180717', 'missing_patch':'27937914, 28247681', 'os':'win', 'component':'db'},
  
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.180717', 'missing_patch':'28317232, 27547329, 28259833, 28349311', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.180717', 'missing_patch':'27937907, 28289029, 28563501', 'os':'win', 'component':'db'},
  
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.180717', 'missing_patch':'28317175, 27734982, 28204707', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.180717', 'missing_patch':'27695940, 28265827', 'os':'win', 'component':'db'},

  # OJVM
  {'min_version': '18.0', 'fixed_version': '18.3.0.0.180717', 'missing_patch':'27923415, 28502229', 'os':'unix', 'component':'ojvm'},
  
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.180717', 'missing_patch':'27923353, 28440725', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.180717', 'missing_patch':'28135129, 28416087', 'os':'win', 'component':'ojvm'},
  
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.180717', 'missing_patch':'27923320, 28440711', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.180717', 'missing_patch':'28135126, 28135128', 'os':'win', 'component':'ojvm'},
  
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.180717', 'missing_patch':'27923163, 28440700', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.180717', 'missing_patch':'28135121, 28416098', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
