#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166370);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id(
    "CVE-2019-2904",
    "CVE-2020-13956",
    "CVE-2020-36518",
    "CVE-2021-3737",
    "CVE-2021-4048",
    "CVE-2021-25122",
    "CVE-2021-25329",
    "CVE-2021-30129",
    "CVE-2021-41495",
    "CVE-2021-41496",
    "CVE-2022-1586",
    "CVE-2022-1587",
    "CVE-2022-2047",
    "CVE-2022-2048",
    "CVE-2022-21540",
    "CVE-2022-21541",
    "CVE-2022-21549",
    "CVE-2022-21596",
    "CVE-2022-21603",
    "CVE-2022-21606",
    "CVE-2022-34169",
    "CVE-2022-34305",
    "CVE-2022-39419"
  );
  script_xref(name:"IAVA", value:"2022-A-0424-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Database Server (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 19c and 21c versions of Oracle Database Server installed on the remote host are affected by multiple
vulnerabilities as referenced in the October 2022 CPU advisory.

  - Vulnerability in the Oracle Database - Machine Learning (Numpy) component of Oracle Database Server. The 
    supported version that is affected is 21c. Easily exploitable vulnerability allows low privileged attacker
    having Create Session privilege with network access via Oracle Net to compromise Oracle Database - Machine
    Learning (Numpy). (CVE-2021-41495)  

  - Vulnerability in the Spatial and Graph (jackson-databind) component of Oracle Database Server. Supported
    versions that are affected are 19c and 21c. Easily exploitable vulnerability allows low privileged attacker
    having Authenticated User privilege with network access via HTTP to compromise Spatial and
    Graph (jackson-databind). Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Spatial and Graph (jackson-databind).
    (CVE-2020-36518)

  - Vulnerability in the Oracle Notification Server (PCRE2) component of Oracle Database Server. Supported
    versions that are affected are 19c and 21c. Easily exploitable vulnerability allows low privileged
    attacker having Subscriber privilege with network access via HTTP to compromise Oracle Notification
    Server (PCRE2). Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle Notification Server (PCRE2).
    Note: This vulnerability applies to Windows systems only. (CVE-2022-1587)

  - Vulnerability in the Oracle Database - Advanced Queuing component of Oracle Database Server. The supported
    version that is affected is 19c. Easily exploitable vulnerability allows high privileged attacker having
    DBA user privilege with network access via Oracle Net to compromise Oracle Database - Advanced Queuing.
    Successful attacks of this vulnerability can result in takeover of Oracle Database - Advanced Queuing.
    (CVE-2022-21596)

  - Vulnerability in the Oracle Database - Sharding component of Oracle Database Server. Supported versions
    that are affected are 19c and 21c. Easily exploitable vulnerability allows high privileged attacker having
    Local Logon privilege with network access via Local Logon to compromise Oracle Database - Sharding.
    Successful attacks of this vulnerability can result in takeover of Oracle Database - Sharding.
    (CVE-2022-21603)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2904");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

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
  {'min_version': '21.0', 'fixed_version': '21.8.0.0.221018', 'missing_patch':'34527084', 'os':'unix', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.8.0.0.221018', 'missing_patch':'34468137', 'os':'win', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.15.2.0.221018', 'missing_patch':'34429835', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.17.0.0.221018', 'missing_patch':'34468114', 'os':'win', 'component':'db'},
  {'min_version': '19.16', 'fixed_version': '19.16.1.0.221018', 'missing_patch':'34444812', 'os':'unix', 'component':'db'},
  {'min_version': '19.17', 'fixed_version': '19.17.0.0.221018', 'missing_patch':'34419443', 'os':'unix', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.17.0.0.221018', 'missing_patch':'34411846', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.17.0.0.221018', 'missing_patch':'34411846', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
