#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121253);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id("CVE-2019-2406", "CVE-2019-2444", "CVE-2019-2547");
  script_bugtraq_id(106584, 106591, 106594);

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jan 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the January 2019
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An authenticated remote database takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, remote attacker with the
    Create Session, Execute Catalog Role privileges can exploit this
    via the Oracle Net protocol to take over the back-end database,
    resulting in the disclosure or manipulation of arbitrary data.
    (CVE-2019-2406)

  - An authenticated local database takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, local attacker with the Local
    Logon privilege can exploit this, by convincing another user to
    perform an unspecified action, to take over the back-end
    database, resulting in the disclosure or manipulation of
    arbitrary data. (CVE-2019-2444)

  - A denial of service (DoS) vulnerability exists in the Oracle
    RDBMS. An authenticated, remote attacker with the Create Session,
    Create Procedure privileges can exploit this issue, via
    multiple network protocols, by convincing another use to perform
    an unspecified action, to cause the Java VM to stop responding.
    (CVE-2019-2547)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f983335e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2406");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

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
  {'min_version': '18.5', 'fixed_version': '18.5.0.0.190115', 'missing_patch':'28822489', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.5.0.0.190115', 'missing_patch':'29124511', 'os':'win', 'component':'db'},
  {'min_version': '18.4', 'fixed_version': '18.4.1.0.190115', 'missing_patch':'28822587', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.3.2.0.190115', 'missing_patch':'28790643', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190115', 'missing_patch':'28822515, 28790640, 28822638', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190115', 'missing_patch':'28810696', 'os':'win', 'component':'db'},
 
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190115', 'missing_patch':'28729169, 28731800', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190115', 'missing_patch':'28810679', 'os':'win', 'component':'db'},
 
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190115', 'missing_patch':'28729262, 28790634', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190115', 'missing_patch':'28761877', 'os':'win', 'component':'db'},

  # OJVM :
  {'min_version': '18.0', 'fixed_version': '18.5.0.0.190115', 'missing_patch':'28790647', 'os':'unix', 'component':'ojvm'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190115', 'missing_patch':'28790651', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190115', 'missing_patch':'28994068', 'os':'win', 'component':'ojvm'},
 
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190115', 'missing_patch':'28790654', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190115', 'missing_patch':'28994063', 'os':'win', 'component':'ojvm'},
 
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190115', 'missing_patch':'28790660', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190115', 'missing_patch':'28994059', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);

