#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118230);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-3259", "CVE-2018-3299", "CVE-2018-7489");
  script_bugtraq_id(103203, 105648);

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (October 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the October 2018 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities, including remote code execution, as noted in the
October 2018 Critical Patch Update advisory. Please consult the CVRF
details for the applicable CVEs for additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c7f8345");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7489");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

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
  {'min_version': '18.4', 'fixed_version': '18.4.0.0.181016', 'missing_patch':'28689117, 28655784', 'os':'unix', 'component':'db'},
  {'min_version': '18.3', 'fixed_version': '18.3.1.0.181016', 'missing_patch':'28507480', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.2.2.0.181016', 'missing_patch':'28601267', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.181016', 'missing_patch':'28689128, 28662603', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.181016', 'missing_patch':'28574555', 'os':'win', 'component':'db'},
 
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.181016', 'missing_patch':'28689146, 28259833', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.181016', 'missing_patch':'28563501', 'os':'win', 'component':'db'},
 
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.181016', 'missing_patch':'28689160, 28204707', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.181016', 'missing_patch':'28265827', 'os':'win', 'component':'db'},

  # OJVM
  {'min_version': '18.0', 'fixed_version': '18.4.0.0.181016', 'missing_patch':'28502229', 'os':'unix', 'component':'ojvm'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.181016', 'missing_patch':'28440725', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.181016', 'missing_patch':'28412312', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.181016', 'missing_patch':'28440711', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.181016', 'missing_patch':'28412299', 'os':'win', 'component':'ojvm'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.181016', 'missing_patch':'28440700', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.181016', 'missing_patch':'28412269', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
