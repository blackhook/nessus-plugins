#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135585);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2016-7103",
    "CVE-2016-10251",
    "CVE-2019-2853",
    "CVE-2019-17563",
    "CVE-2020-2514",
    "CVE-2020-2734",
    "CVE-2020-2735",
    "CVE-2020-2737"
  );
  script_bugtraq_id(97584, 104823, 109236);
  script_xref(name:"IAVA", value:"2020-A-0147-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the April 2020 Critical Patch Update (CPU). It is, therefore, affected
by multiple vulnerabilities:
  - Vulnerability in the Oracle Multimedia component of Oracle Database Server. The supported version that is
    affected is 12.1.0.2. Easily exploitable vulnerability allows low privileged attacker having Create
    Session privilege with network access via Oracle Net to compromise Oracle Multimedia. Successful attacks
    require human interaction from a person other than the attacker. Successful attacks of this vulnerability
    can result in takeover of Oracle Multimedia (CVE-2016-10251).

  - Vulnerability in the Oracle Application Express component of Oracle Database Server. The supported
  version that is affected is Prior to 19.1. Easily exploitable vulnerability allows unauthenticated attacker
  with network access via HTTPS to compromise Oracle Application Express. Successful attacks require human
  interaction from a person other than the attacker and while the vulnerability is in Oracle Application
  Express, attacks may significantly impact additional products. Successful attacks of this vulnerability
  can result in unauthorized update, insert or delete access to some of Oracle Application Express accessible
  data as well as unauthorized read access to a subset of Oracle Application Express accessible data
  (CVE-2016-7103).

  - Vulnerability in the WLM (Apache Tomcat) component of Oracle Database Server. Supported versions that
  are affected are 12.2.0.1, 18c and 19c. Difficult to exploit vulnerability allows unauthenticated attacker
  with network access via HTTPS to compromise WLM (Apache Tomcat). Successful attacks require human
  interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
  takeover of WLM (Apache Tomcat) (CVE-2019-17563).

It is also affected by additional vulnerabilities; see the vendor advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?279de7b8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2853");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

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
  {'min_version': '19.7', 'fixed_version': '19.7.0.0.200414', 'missing_patch':'30869156', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.7.0.0.200414', 'missing_patch':'30901317', 'os':'win', 'component':'db'},
  {'min_version': '19.6', 'fixed_version': '19.6.1.0.200414', 'missing_patch':'30797938', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.5.2.0.200414', 'missing_patch':'30830913', 'os':'unix', 'component':'db'},

  {'min_version': '18.10', 'fixed_version': '18.10.0.0.200414', 'missing_patch':'30872794', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.10.0.0.200414', 'missing_patch':'30901451', 'os':'win', 'component':'db'},
  {'min_version': '18.9', 'fixed_version': '18.9.1.0.200414', 'missing_patch':'30798089', 'os':'unix', 'component':'db'},
  {'min_version': '18.0', 'fixed_version': '18.8.2.0.200414', 'missing_patch':'30830887', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.200414', 'missing_patch':'30799484, 30831066, 30886680', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.200414', 'missing_patch':'30861472', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.200414', 'missing_patch':'30691015, 30700212', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.200414', 'missing_patch':'30861721', 'os':'win', 'component':'db'},

  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.200414', 'missing_patch':'30670774, 30691206, 31010960', 'os':'unix', 'component':'db'},
  {'min_version': '11.2.0.4', 'fixed_version': '11.2.0.4.200414', 'missing_patch':'31169916', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.7.0.0.200414', 'missing_patch':'30805684', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.7.0.0.200414', 'missing_patch':'30805684', 'os':'win', 'component':'ojvm'},

  {'min_version': '18.0',  'fixed_version': '18.10.0.0.200414', 'missing_patch':'30805598', 'os':'unix', 'component':'ojvm'},
  {'min_version': '18.0',  'fixed_version': '18.10.0.0.200414', 'missing_patch':'30805598', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.200414', 'missing_patch':'30805580', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.200414', 'missing_patch':'31035002', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.200414', 'missing_patch':'30805558', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.200414', 'missing_patch':'31037459', 'os':'win', 'component':'ojvm'},

  {'min_version': '11.2.0.4',  'fixed_version': '11.2.0.4.200414', 'missing_patch':'30805543', 'os':'unix', 'component':'ojvm'},
  {'min_version': '11.2.0.4',  'fixed_version': '11.2.0.4.200414', 'missing_patch':'31169933', 'os':'win', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
