#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170192);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2020-10735",
    "CVE-2020-10878",
    "CVE-2021-3737",
    "CVE-2021-29338",
    "CVE-2021-37750",
    "CVE-2022-1122",
    "CVE-2022-3171",
    "CVE-2022-21597",
    "CVE-2022-39429",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2022-42889",
    "CVE-2022-45047",
    "CVE-2023-21827",
    "CVE-2023-21829",
    "CVE-2023-21893"
  );
  script_xref(name:"IAVA", value:"2023-A-0035-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Database Server for Windows (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2023 CPU advisory.

  - Vulnerability in the Oracle Data Provider for .NET component of Oracle Database Server. Supported versions
    that are affected are 19c and 21c. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via TCPS to compromise Oracle Data Provider for .NET. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    takeover of Oracle Data Provider for .NET. Note: Applies also to Database client-only on Windows platform.
    (CVE-2023-21893)

  - Vulnerability in the Oracle Database - Machine Learning for Python (Python) component of Oracle Database
    Server. The supported version that is affected is 21c. Easily exploitable vulnerability allows low
    privileged attacker having Database User privilege with network access via Oracle Net to compromise Oracle
    Database - Machine Learning for Python (Python). Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Database -
    Machine Learning for Python (Python). (CVE-2021-3737)

  - Vulnerability in the Oracle Database RDBMS Security component of Oracle Database Server. Supported
    versions that are affected are 19c and 21c. Easily exploitable vulnerability allows low privileged
    attacker having Create Session privilege with network access via Oracle Net to compromise Oracle Database
    RDBMS Security. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Oracle Database RDBMS Security accessible data as well as unauthorized read
    access to a subset of Oracle Database RDBMS Security accessible data. (CVE-2023-21829)

  - Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected are
    19c and 21c. Easily exploitable vulnerability allows low privileged attacker having Create Procedure
    privilege with network access via Oracle Net to compromise Java VM. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java VM. (CVE-2022-39429)

  - Vulnerability in the Oracle Database Data Redaction component of Oracle Database Server. Supported
    versions that are affected are 19c and 21c. Easily exploitable vulnerability allows low privileged
    attacker having Create Session privilege with network access via Oracle Net to compromise Oracle Database
    Data Redaction. Successful attacks of this vulnerability can result in unauthorized read access to a
    subset of Oracle Database Data Redaction accessible data. (CVE-2023-21827)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from CVE-2023-21829");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Score from CVE-2023-21893");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '21.0', 'fixed_version': '21.9.0.0.230117', 'missing_patch':'34750812', 'os':'win', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.18.0.0.230117', 'missing_patch':'34750795', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.18.0.0.230117', 'missing_patch':'34786990', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
