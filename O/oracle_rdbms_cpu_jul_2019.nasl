#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126830);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-9572",
    "CVE-2018-11058",
    "CVE-2019-2484",
    "CVE-2019-2569",
    "CVE-2019-2749",
    "CVE-2019-2753",
    "CVE-2019-2776",
    "CVE-2019-2799"
  );
  script_bugtraq_id(
    108106,
    109195,
    109203,
    109211,
    109214,
    109217,
    109224,
    109233
  );

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jul 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the July 2019 Critical Patch Update (CPU). It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified vulnerability in the Spatial component of Oracle Database Server, which could allow an
    authenticated, remote attacker to cause a partial denial of service of Spatial. (CVE-2016-9572)

  - An unspecified vulnerability in the Core RDBMS component of Oracle Database Server, which could allow an
    unauthenticated, remote attacker to take over Core RDBMS (CVE-2018-11058)

  - An unspecified vulnerability in the Application Express component of Oracle Database Server, which could allow an
    authenticated, remote attacker to manipulate Application Express accessible data. (CVE-2019-2484)

  - An unspecified vulnerability in the Core RDBMS component of Oracle Database Server, which could allow an
    authenticated, local attacker complete access to all Core RDBMS accessible data. (CVE-2019-2569)

  - An unspecified vulnerability in the Java VM component of Oracle Database Server, which could allow an
    authenticated, remote attacker to manipulate Java VM accessible data or cause a complete denial of service of
    Java VM. (CVE-2019-2749)

  - An unspecified vulnerability in the Oracle Text component of Oracle Database Server, which could allow an
    authenticated, remote attacker to read a subset of Oracle Text accessible data or cause a partial denial of service
    of Oracle Text. (CVE-2019-2753)

  - An unspecified vulnerability in the Core RDBMS component of Oracle Database Server, which could allow an
    authenticated, remote attacker complete access to all Core RDBMS accessible data. (CVE-2019-2776)

  - An unspecified vulnerability in the Oracle ODBC Driver component of Oracle Database Server, which could allow an
    authenticated, remote attacker to take over Oracle ODBC Driver. Note this vulnerability only affects the Windows
    platform. (CVE-2019-2799)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d1d765d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
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
  {'min_version': '19.0', 'fixed_version': '19.4.0.0.190716', 'missing_patch':'29708769, 29834717', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.4.0.0.190716', 'missing_patch':'29859191', 'os':'win', 'component':'db'},

  {'min_version': '18.7', 'fixed_version': '18.7.0.0.190716', 'missing_patch':'29708703, 29757256', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.7.0.0.190716', 'missing_patch':'29859180', 'os':'win', 'component':'db'},
  {'min_version': '18.6', 'fixed_version': '18.6.1.0.190716', 'missing_patch':'29708235', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.5.2.0.190716', 'missing_patch':'29708437', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190716', 'missing_patch':'29708381, 29708478, 29757449', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190716', 'missing_patch':'29832062', 'os':'win', 'component':'db'},
 
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190716', 'missing_patch':'29496791, 29494060', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190716', 'missing_patch':'29831650', 'os':'win', 'component':'db'},
 
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190716', 'missing_patch':'29698813, 29497421', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190716', 'missing_patch':'29596609', 'os':'win', 'component':'db'},

  # OJVM :
  {'min_version': '19.0', 'fixed_version': '19.4.0.0.190716', 'missing_patch':'29774421', 'os':'unix', 'component':'ojvm'},

  {'min_version': '18.0', 'fixed_version': '18.7.0.0.190716', 'missing_patch':'29774410', 'os':'unix', 'component':'ojvm'},
  {'min_version': '18.0', 'fixed_version': '18.7.0.0.190716', 'missing_patch':'29774410', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190716', 'missing_patch':'29774415', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190716', 'missing_patch':'29837425', 'os':'win', 'component':'ojvm'},
 
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190716', 'missing_patch':'29774383', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190716', 'missing_patch':'29837393', 'os':'win', 'component':'ojvm'},
 
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190716', 'missing_patch':'29610422', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190716', 'missing_patch':'30012911', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);

