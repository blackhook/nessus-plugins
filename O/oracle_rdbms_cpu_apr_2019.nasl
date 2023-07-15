#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124155);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id(
    "CVE-2019-2516",
    "CVE-2019-2517",
    "CVE-2019-2518",
    "CVE-2019-2571",
    "CVE-2019-2582",
    "CVE-2019-2619"
  );
  script_bugtraq_id(
    107919,
    107936,
    107940,
    107945
  );

  script_xref(name:"IAVA", value:"2019-A-0123-S");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Apr 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the April 2019
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An authenticated local Portable Clusterware takeover
    vulnerability exists in the Oracle RDBMS. An authenticated, local
    attacker with the Grid Infrastructure User privilege with logon
    to the infrastructure where Portable Clusterware executes can
    exploit this to take over the Portable Clusterware component of
    Oracle RDBMS, resulting in the disclosure or manipulation of
    arbitrary data. (CVE-2019-2516) (CVE-2019-2619)

  - An authenticated remote database takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, remote attacker with the
    DBFS_ROLE privilege can exploit this via the Oracle Net protocol
    to take over the back-end database, resulting in the disclosure
    or manipulation of arbitrary data. (CVE-2019-2517)

  - An authenticated remote Java VM takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, remote attacker with the
    Create Session, Create Procedure privileges can exploit this to
    take over the Java VM. (CVE-2019-2518)

  - An authenticated remote RDBMS DataPump takeover vulnerability
    exists in the Oracle RDBMS. An authenticated, remote attacker
    with the DBA role privilege can exploit this via the Oracle Net
    protocol to take over the RDBMS DataPump component of Oracle
    RDBMS. (CVE-2019-2571)

  - An unauthenticated remote information disclosure vulnerability
    exists in the Oracle RDBMS. An unauthenticated, remote attacker
    can exploit this via the Oracle Net protocol to obtain read
    access to a unspecified subset of Core RDBMS accessible data.
    (CVE-2019-2582)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee33210c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  {'min_version': '18.6', 'fixed_version': '18.6.0.0.190416', 'missing_patch':'29301631', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.6.0.0.190416', 'missing_patch':'29589622', 'os':'win', 'component':'db'},
  {'min_version': '18.5', 'fixed_version': '18.5.1.0.190416', 'missing_patch':'29230887', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.4.2.0.190416', 'missing_patch':'29230809', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190416', 'missing_patch':'29314339, 29230821, 29230950', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190416', 'missing_patch':'29394003', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190416', 'missing_patch':'29141015, 29141038', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190416', 'missing_patch':'29413116', 'os':'win', 'component':'db'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190416', 'missing_patch':'29141056, 29257245', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190416', 'missing_patch':'29218820', 'os':'win', 'component':'db'},


  # OJVM :
  {'min_version': '19.0', 'fixed_version': '19.3.0.0.190416', 'missing_patch':'29548437', 'os':'unix', 'component':'ojvm'},

  {'min_version': '18.0', 'fixed_version': '18.6.0.0.190416', 'missing_patch':'29249584', 'os':'unix', 'component':'ojvm'},
  {'min_version': '18.0', 'fixed_version': '18.6.0.0.190416', 'missing_patch':'29249584', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190416', 'missing_patch':'29249637', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1', 'fixed_version': '12.2.0.1.190416', 'missing_patch':'29281550', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190416', 'missing_patch':'29251241', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2', 'fixed_version': '12.1.0.2.190416', 'missing_patch':'29447962', 'os':'win', 'component':'ojvm'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190416', 'missing_patch':'29251270', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.190416', 'missing_patch':'29447971', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
