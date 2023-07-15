#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174470);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-1471",
    "CVE-2022-37454",
    "CVE-2022-42919",
    "CVE-2022-45061",
    "CVE-2022-45143",
    "CVE-2023-21918",
    "CVE-2023-21934",
    "CVE-2023-24998"
  );
  script_xref(name:"IAVA", value:"2023-A-0205");

  script_name(english:"Oracle Oracle Database Server (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 19c and 21c versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities
as referenced in the April 2023 CPU advisory.

  - Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected
    are 19c and 21c. Difficult to exploit vulnerability allows low privileged attacker having User Account
    privilege with network access via TLS to compromise Java VM. Successful attacks of this vulnerability
    can result in unauthorized creation, deletion or modification access to critical data or all Java VM
    accessible data as well as unauthorized access to critical data or complete access to all Java VM
    accessible data. (CVE-2023-21934)

  - Vulnerability in the Oracle Database Recovery Manager component of Oracle Database Server. Supported
    versions that are affected are 19c and 21c. Easily exploitable vulnerability allows high privileged
    attacker having Local SYSDBA privilege with network access via Oracle Net to compromise Oracle Database
    Recovery Manager. While the vulnerability is in Oracle Database Recovery Manager, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle
    Database Recovery Manager. (CVE-2023-21918)

  - Vulnerability in the Oracle Database Workload Manager (Apache Commons FileUpload) component of Oracle
    Database Server. The supported version that is affected is 21c. Easily exploitable vulnerability allows
    low privileged attacker having Authenticated User privilege with network access via HTTP to compromise
    Oracle Database Workload Manager (Apache Commons FileUpload). Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of
    Oracle Database Workload Manager (Apache Commons FileUpload). (CVE-2023-24998)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"CVSS vector from vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

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

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '21.0', 'fixed_version': '21.10.0.0.230418', 'missing_patch':'35134934', 'os':'unix', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.10.0.0.230418', 'missing_patch':'35046488', 'os':'win', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.19.0.0.230418', 'missing_patch':'35042068', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.19.0.0.230418', 'missing_patch':'35046439', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.19.0.0.230418', 'missing_patch':'35050341', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.19.0.0.230418', 'missing_patch':'35050341', 'os':'win', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
