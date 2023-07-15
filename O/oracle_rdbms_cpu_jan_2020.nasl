#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133047);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id(
    "CVE-2019-10072",
    "CVE-2020-2510",
    "CVE-2020-2511",
    "CVE-2020-2512",
    "CVE-2020-2515",
    "CVE-2020-2516",
    "CVE-2020-2517",
    "CVE-2020-2518",
    "CVE-2020-2527",
    "CVE-2020-2568",
    "CVE-2020-2569",
    "CVE-2020-2731"
  );
  script_bugtraq_id(108874);
  script_xref(name:"IAVA", value:"2020-A-0020-S");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the January 2020 Critical Patch Update (CPU). It is, therefore, affected
by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability exists in the Core RDBMS component of Oracle Database Server. An
    authenticated, remote attacker can exploit this issue, to cause the application to stop responding.
    (CVE-2020-2511)

  - A remote code execution vulnerability exists in the Core RDBMS component of Oracle Database Server. An
    unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands.
    (CVE-2020-2510)

  - An unspecified vulnerability exists in the JavaVM component of Oracle Database Server. An authenicated,
    remote attacker can exploit this issue, to affect the confidentiality, integrity and availability of the
    application.

It is also affected by additional vulnerabilities; see the vendor advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpujan2020.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58180da1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2510");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

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
  {'min_version': '19.6', 'fixed_version': '19.6.0.0.200114', 'missing_patch':'30557433', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.6.0.0.200114', 'missing_patch':'30445947', 'os':'win', 'component':'db'},
  {'min_version': '19.5', 'fixed_version': '19.5.1.0.200114', 'missing_patch':'30446054', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.4.2.0.200114', 'missing_patch':'30446228', 'os':'unix', 'component':'db'},

  {'min_version': '18.9', 'fixed_version': '18.9.0.0.200114', 'missing_patch':'30480385', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.9.0.0.200114', 'missing_patch':'30445951', 'os':'win', 'component':'db'},
  {'min_version': '18.8', 'fixed_version': '18.8.1.0.200114', 'missing_patch':'30445895', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.7.2.0.200114', 'missing_patch':'30446239', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.200114', 'missing_patch':'30445968, 30446254, 30593149', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.200114', 'missing_patch':'30446296', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.200114', 'missing_patch':'30340202, 30364137', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.200114', 'missing_patch':'30455401', 'os':'win', 'component':'db'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.200114', 'missing_patch':'30298532, 30310975, 30559616', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.200114', 'missing_patch':'30502376', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.6.0.0.200114', 'missing_patch':'30484981', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.6.0.0.200114', 'missing_patch':'30484981', 'os':'win', 'component':'ojvm'},

  {'min_version': '18.0',  'fixed_version': '18.9.0.0.200114', 'missing_patch':'30501926', 'os':'unix', 'component':'ojvm'},
  {'min_version': '18.0',  'fixed_version': '18.9.0.0.200114', 'missing_patch':'30501926', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.200114', 'missing_patch':'30502018', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.200114', 'missing_patch':'30525838', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.200114', 'missing_patch':'30502041', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.200114', 'missing_patch':'30671054', 'os':'win', 'component':'ojvm'},

  {'min_version': '11.2.0.4',  'fixed_version': '11.2.0.4.200114', 'missing_patch':'30503372', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4',  'fixed_version': '11.2.0.4.200114', 'missing_patch':'30671044', 'os':'win', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
