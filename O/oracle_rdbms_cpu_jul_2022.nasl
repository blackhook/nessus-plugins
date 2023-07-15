##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163408);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/08");

  script_cve_id(
    "CVE-2020-29505",
    "CVE-2020-29506",
    "CVE-2020-29507",
    "CVE-2020-35167",
    "CVE-2020-35169",
    "CVE-2021-41184",
    "CVE-2021-45943",
    "CVE-2022-0839",
    "CVE-2022-21432",
    "CVE-2022-21510",
    "CVE-2022-21511",
    "CVE-2022-21565",
    "CVE-2022-24729",
    "CVE-2022-24891"
  );
  script_xref(name:"IAVA", value:"2022-A-0283");

  script_name(english:"Oracle Oracle Database Server (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.1.0.2, 19c, 21c, All Supported Versions, and None versions of Oracle Database Server installed on the remote host
are affected by multiple vulnerabilities as referenced in the July 2022 CPU advisory.

  - Vulnerability in the Oracle Database - Enterprise Edition Sharding component of Oracle Database Server.
    For supported versions that are affected see note. Easily exploitable vulnerability allows low privileged
    attacker having Local Logon privilege with logon to the infrastructure where Oracle Database - Enterprise
    Edition Sharding executes to compromise Oracle Database - Enterprise Edition Sharding. While the
    vulnerability is in Oracle Database - Enterprise Edition Sharding, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in takeover of
    Oracle Database - Enterprise Edition Sharding. (CVE-2022-21510)

  - Vulnerability in the Oracle Database - Enterprise Edition Recovery component of Oracle Database Server. For
    supported versions that are affected see note. Easily exploitable vulnerability allows high privileged
    attacker having EXECUTE ON DBMS_IR.EXECUTESQLSCRIPT privilege with network access via Oracle Net to compromise Oracle
    Database - Enterprise Edition Recovery. Successful attacks of this vulnerability can result in takeover of
    Oracle Database - Enterprise Edition Recovery. Note: None of the supported versions are affected. (CVE-2022-21511)

  - Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected are
    12.1.0.2, 19c and 21c. Easily exploitable vulnerability allows low privileged attacker having Create Procedure
    privilege with network access via Oracle Net to compromise Java VM. Successful attacks of this vulnerability
    can result in unauthorized creation, deletion or modification access to critical data or all Java VM accessible
    data. (CVE-2022-21565)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0839");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '21.0', 'fixed_version': '21.7.0.0.220719', 'missing_patch':'34160444', 'os':'unix', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.7.0.0.220719', 'missing_patch':'34110698', 'os':'win', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.14.2.0.220719', 'missing_patch':'34110559', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.16.0.0.220719', 'missing_patch':'34110685', 'os':'win', 'component':'db'},
  {'min_version': '19.15', 'fixed_version': '19.15.1.0.220719', 'missing_patch':'34119532', 'os':'unix', 'component':'db'},
  {'min_version': '19.16', 'fixed_version': '19.16.0.0.220719', 'missing_patch':'34133642', 'os':'unix', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.220719', 'missing_patch':'34057742, 34057733', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.220719', 'missing_patch':'33883271', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.16.0.0.220719', 'missing_patch':'34086870', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.16.0.0.220719', 'missing_patch':'34086870', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.220719', 'missing_patch':'34086863', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.220719', 'missing_patch':'34185253', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
