#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154332);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2020-27824",
    "CVE-2021-2332",
    "CVE-2021-25122",
    "CVE-2021-26272",
    "CVE-2021-29425",
    "CVE-2021-29921",
    "CVE-2021-35551",
    "CVE-2021-35557",
    "CVE-2021-35558",
    "CVE-2021-35576",
    "CVE-2021-35599",
    "CVE-2021-35619"
  );
  script_xref(name:"IAVA", value:"2021-A-0263-S");
  script_xref(name:"IAVA", value:"2021-A-0483");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (October 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2021 CPU advisory.

  - Vulnerability in the Zero Downtime DB Migration to Cloud component of Oracle Database Server. The
    supported version that is affected is 21c. Easily exploitable vulnerability allows high privileged
    attacker having Local Logon privilege with logon to the infrastructure where Zero Downtime DB Migration to
    Cloud executes to compromise Zero Downtime DB Migration to Cloud. While the vulnerability is in Zero
    Downtime DB Migration to Cloud, attacks may significantly impact additional products. Successful attacks
    of this vulnerability can result in takeover of Zero Downtime DB Migration to Cloud. (CVE-2021-35599)

  - Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected are
    12.1.0.2, 12.2.0.1, 19c and 21c. Difficult to exploit vulnerability allows low privileged attacker having
    Create Procedure privilege with network access via Oracle Net to compromise Java VM. Successful attacks
    require human interaction from a person other than the attacker. Successful attacks of this vulnerability
    can result in takeover of Java VM. (CVE-2021-35619)

  - Vulnerability in the Oracle LogMiner component of Oracle Database Server. Supported versions that are
    affected are 12.1.0.2, 12.2.0.1 and 19c. Easily exploitable vulnerability allows high privileged attacker
    having DBA privilege with network access via Oracle Net to compromise Oracle LogMiner. Successful attacks
    of this vulnerability can result in unauthorized creation, deletion or modification access to critical
    data or all Oracle LogMiner accessible data as well as unauthorized read access to a subset of Oracle
    LogMiner accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of Oracle LogMiner. (CVE-2021-2332)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29921");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:

  # Note there are no Combo or OJVM patches for 21.x. OJVM fixes are released as part of the RU patches.
  # See note next to 21.x patches for Oct 21': http://www.nessus.org/u?d4ca86db
  {'min_version': '21.0', 'fixed_version': '21.4.0.0.211019', 'missing_patch':'33239276', 'os':'unix', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.11.2.0.211019', 'missing_patch':'33153989', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.13.0.0.211019', 'missing_patch':'33155330', 'os':'win', 'component':'db'},
  {'min_version': '19.12', 'fixed_version': '19.12.1.0.211019', 'missing_patch':'33210889', 'os':'unix', 'component':'db'},
  {'min_version': '19.13', 'fixed_version': '19.13.0.0.211019', 'missing_patch':'33192793', 'os':'unix', 'component':'db'}, 
 
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.211019', 'missing_patch':'33261817', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.211019', 'missing_patch':'33174380', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.211019', 'missing_patch':'33248411, 33128590', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.211019', 'missing_patch':'33174365', 'os':'win', 'component':'db'},
  
  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.13.0.0.211019', 'missing_patch':'33192694', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.13.0.0.211019', 'missing_patch':'33192694', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.211019', 'missing_patch':'33192662', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.211019', 'missing_patch':'33248852', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.211019', 'missing_patch':'33192628', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.211019', 'missing_patch':'33248785', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
