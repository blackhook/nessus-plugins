#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141829);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-12900",
    "CVE-2020-9281",
    "CVE-2020-11023",
    "CVE-2020-13935",
    "CVE-2020-14734",
    "CVE-2020-14735",
    "CVE-2020-14736",
    "CVE-2020-14740",
    "CVE-2020-14741",
    "CVE-2020-14742",
    "CVE-2020-14743",
    "CVE-2020-14762",
    "CVE-2020-14763",
    "CVE-2020-14898",
    "CVE-2020-14899",
    "CVE-2020-14900",
    "CVE-2020-14901"
  );
  script_xref(name:"IAVA", value:"2020-A-0475");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2020 CPU advisory.

  - Vulnerability in the Core RDBMS (bzip2) component of Oracle Database Server. Supported versions that are 
  affected are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows low 
  privileged attacker having DBA Level Account privilege with network access via Oracle Net to compromise 
  Core RDBMS (bzip2). Successful attacks of this vulnerability can result in takeover of Core RDBMS (bzip2).
  (CVE-2019-12900)
  
  - Vulnerability in the Core RDBMS (bzip2) component of Oracle Database Server. Supported versions that 
  are affected are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows low 
  privileged attacker having DBA Level Account privilege with network access via Oracle Net to compromise 
  Core RDBMS (bzip2). Successful attacks of this vulnerability can result in takeover of Core RDBMS (bzip2).
  (CVE-2020-14735)

  - Vulnerability in the Oracle Text component of Oracle Database Server. Supported versions that are affected
  are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Difficult to exploit vulnerability allows unauthenticated 
  attacker with network access via Oracle Net to compromise Oracle Text. Successful attacks of this 
  vulnerability can result in takeover of Oracle Text. (CVE-2020-14734)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12900");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '19.9', 'fixed_version': '19.9.0.0.201020', 'missing_patch':'31771877', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.9.0.0.201020', 'missing_patch':'31719903', 'os':'win', 'component':'db'},
  {'min_version': '19.8', 'fixed_version': '19.8.1.0.201020', 'missing_patch':'31666885', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.7.2.0.201020', 'missing_patch':'31667176', 'os':'unix', 'component':'db'},

  {'min_version': '18.12', 'fixed_version': '18.12.0.0.201020', 'missing_patch':'31730250', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.12.0.0.201020', 'missing_patch':'31629682', 'os':'win', 'component':'db'},
  {'min_version': '18.11', 'fixed_version': '18.11.1.0.201020', 'missing_patch':'31666917', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.10.2.0.201020', 'missing_patch':'31667173', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.201020', 'missing_patch':'31741641, 31667168, 31666944', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.201020', 'missing_patch':'31654782', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.201020', 'missing_patch':'31550110, 31511219', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.201020', 'missing_patch':'31658987', 'os':'win', 'component':'db'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.201020', 'missing_patch':'31537677, 31834759, 31537652', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.201020', 'missing_patch':'31659823', 'os':'win', 'component':'db'},

# OJVM 
  {'min_version': '19.0',  'fixed_version': '19.9.0.0.201020', 'missing_patch':'31668882', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.9.0.0.201020', 'missing_patch':'31668882', 'os':'win', 'component':'ojvm'},

  {'min_version': '18.0',  'fixed_version': '18.12.0.0.201020', 'missing_patch':'31668892', 'os':'unix', 'component':'ojvm'},
  {'min_version': '18.0',  'fixed_version': '18.12.0.0.201020', 'missing_patch':'31668892', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.201020', 'missing_patch':'31668898', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.201020', 'missing_patch':'31740064', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.201020', 'missing_patch':'31668915', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.201020', 'missing_patch':'31740134', 'os':'win', 'component':'ojvm'},

  {'min_version': '11.2.0.4',  'fixed_version': '11.2.0.4.201020', 'missing_patch':'31668908', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4',  'fixed_version': '11.2.0.4.201020', 'missing_patch':'31740195', 'os':'win', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
