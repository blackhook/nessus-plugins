#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145266);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-10878",
    "CVE-2021-1993",
    "CVE-2021-2000",
    "CVE-2021-2018",
    "CVE-2021-2035",
    "CVE-2021-2045",
    "CVE-2021-2054",
    "CVE-2021-2116",
    "CVE-2021-2117"
  );
  script_xref(name:"IAVA", value:"2021-A-0030");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a database server which is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2021 CPU advisory.

  - Vulnerability in the RDBMS Scheduler component of Oracle Database Server. Supported versions that are
    affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows low privileged
    attacker having Export Full Database privilege with network access via Oracle Net to compromise RDBMS
    Scheduler. Successful attacks of this vulnerability can result in takeover of RDBMS Scheduler. (CVE-2021-2035)

  - Vulnerability in the Advanced Networking Option component of Oracle Database Server. Supported versions
    that are affected are 18c and 19c. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via Oracle Net to compromise Advanced Networking Option. Successful attacks require human
    interaction from a person other than the attacker and while the vulnerability is in Advanced Networking
    Option, attacks may significantly impact additional products. Successful attacks of this vulnerability can
    result in takeover of Advanced Networking Option. Note: CVE-2021-2018 affects Windows platform only. (CVE-2021-2018)

  - Vulnerability in the RDBMS Sharding component of Oracle Database Server. Supported versions that are
    affected are 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker
    having Create Any Procedure, Create Any View, Create Any Trigger privilege with network access via Oracle
    Net to compromise RDBMS Sharding. Successful attacks of this vulnerability can result in takeover of RDBMS
    Sharding. (CVE-2021-2054)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2035");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

app_info = vcf::oracle_rdbms::get_app_info();


constraints = [
  # RDBMS:
  {'min_version': '19.0', 'fixed_version': '19.8.2.0.210119', 'missing_patch':'32066676', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.10.0.0.210119', 'missing_patch':'32062765', 'os':'win', 'component':'db'},
  {'min_version': '19.9', 'fixed_version': '19.9.1.0.210119', 'missing_patch':'32072711', 'os':'unix', 'component':'db'},
  {'min_version': '19.10', 'fixed_version': '19.10.0.0.210119', 'missing_patch':'32218454', 'os':'unix', 'component':'db'},
  
  {'min_version': '18.0',  'fixed_version': '18.11.2.0.210119', 'missing_patch':'32066686', 'os':'unix', 'component':'db'},
  {'min_version': '18.0',  'fixed_version': '18.13.0.0.210119', 'missing_patch':'32062760', 'os':'win', 'component':'db'},
  {'min_version': '18.12', 'fixed_version': '18.12.1.0.210119', 'missing_patch':'32072459', 'os':'unix', 'component':'db'},
  {'min_version': '18.13', 'fixed_version': '18.13.0.0.210119', 'missing_patch':'32204699', 'os':'unix', 'component':'db'},
 
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.210119', 'missing_patch':'32228578', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.210119', 'missing_patch':'31987852', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.210119', 'missing_patch':'31985579, 31965033', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.210119', 'missing_patch':'32000405', 'os':'win', 'component':'db'},
  
  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.10.0.0.210119', 'missing_patch':'32067171', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.10.0.0.210119', 'missing_patch':'32067171', 'os':'win', 'component':'ojvm'},

  {'min_version': '18.0',  'fixed_version': '18.13.0.0.210119', 'missing_patch':'32119939', 'os':'unix', 'component':'ojvm'},
  {'min_version': '18.0',  'fixed_version': '18.13.0.0.210119', 'missing_patch':'32119939', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.210119', 'missing_patch':'32119931', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.210119', 'missing_patch':'32142294', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.210119', 'missing_patch':'32119956', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.210119', 'missing_patch':'32142066', 'os':'win', 'component':'ojvm'}
 
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);

