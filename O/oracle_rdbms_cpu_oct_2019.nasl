#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130058);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id(
    "CVE-2018-2875",
    "CVE-2018-8034",
    "CVE-2018-11784",
    "CVE-2018-14719",
    "CVE-2018-14720",
    "CVE-2018-14721",
    "CVE-2018-19360",
    "CVE-2018-19361",
    "CVE-2018-19362",
    "CVE-2018-1000873",
    "CVE-2019-2734",
    "CVE-2019-2909",
    "CVE-2019-2913",
    "CVE-2019-2939",
    "CVE-2019-2940",
    "CVE-2019-2954",
    "CVE-2019-2955",
    "CVE-2019-2956"
  );
  script_xref(name:"IAVA", value:"2019-A-0379-S");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the October 2019 Critical Patch Update (CPU). It is, therefore, affected
by multiple vulnerabilities :

  - An unspecified vulnerability in the Java VM component of Oracle Database Server, which could allow an
    unauthenticated, remote attacker to manipulate Java VM accessible data. (CVE-2019-2909)

  - An unspecified vulnerability in the Core RDBMS (jackson-databind) component of Oracle Database Server,
    which could allow an authenticated, remote attacker to cause a denial of serivce of Core RDBMS. (CVE-2019-2956)

  - An unspecified vulnerability in the Core RDBMS component of Oracle Database Server, which could allow an
    authenticated, remote attacker to read a subset of Core RDBMS accessible data. (CVE-2019-2913)

It is also affected by additional vulnerabilities; see the vendor advisory for more information.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb3a89d4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2019 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19362");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14721");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '19.5', 'fixed_version': '19.5.0.0.191015', 'missing_patch':'30125133', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.5.0.0.191015', 'missing_patch':'30151705', 'os':'win', 'component':'db'},
  {'min_version': '19.4', 'fixed_version': '19.4.1.0.191015', 'missing_patch':'30080447', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.3.2.0.191015', 'missing_patch':'30087906', 'os':'unix', 'component':'db'},

  {'min_version': '18.8', 'fixed_version': '18.8.0.0.191015', 'missing_patch':'30112122', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.8.0.0.191015', 'missing_patch':'30150321', 'os':'win', 'component':'db'},
  {'min_version': '18.7', 'fixed_version': '18.7.0.0.191015', 'missing_patch':'30080518', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.6.0.0.191015', 'missing_patch':'30087881', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.191015', 'missing_patch':'30087824, 30087848, 30138470', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.191015', 'missing_patch':'30150416', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.191015', 'missing_patch':'29972716, 29918340', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.191015', 'missing_patch':'30049606', 'os':'win', 'component':'db'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.191015', 'missing_patch':'29938470, 29938455, 29509309, 29913194, 30237239', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.191015', 'missing_patch':'30151661', 'os':'win', 'component':'db'},

  # OJVM :
  {'min_version': '19.0', 'fixed_version': '19.5.0.0.191015', 'missing_patch':'30128191', 'os':'unix', 'component':'ojvm'},

  {'min_version': '18.0', 'fixed_version': '18.8.0.0.191015', 'missing_patch':'30133603', 'os':'unix', 'component':'ojvm'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.191015', 'missing_patch':'30133625', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.191015', 'missing_patch':'30268021', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.191015', 'missing_patch':'30128197', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.191015', 'missing_patch':'30268189', 'os':'win', 'component':'ojvm'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.191015', 'missing_patch':'30132974', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.191015', 'missing_patch':'30268157', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
