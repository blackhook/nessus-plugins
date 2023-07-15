#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156822);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2021-32723", "CVE-2022-21247", "CVE-2022-21393");
  script_xref(name:"IAVA", value:"2022-A-0032-S");

  script_name(english:"Oracle Database Server (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2022 CPU advisory.

  - Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected are
    12.1.0.2, 12.2.0.1, 19c and 21c. Easily exploitable vulnerability allows low privileged attacker having
    Create Procedure privilege with network access via Oracle Net to compromise Java VM. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS)
    of Java VM. (CVE-2022-21393)

  - Vulnerability in the Oracle Application Express (Prism) component of Oracle Database Server. The supported
    version that is affected is Prior to 21.1.4. Easily exploitable vulnerability allows low privileged
    attacker having Valid User Account privilege with network access via HTTP to compromise Oracle Application
    Express (Prism). Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Oracle Application Express (Prism). (CVE-2021-32723)

  - Vulnerability in the Core RDBMS component of Oracle Database Server. Supported versions that are affected
    are 12.2.0.1 and 19c. Easily exploitable vulnerability allows high privileged attacker having Create
    Session, Execute Catalog Role privilege with network access via Oracle Net to compromise Core RDBMS.
    Successful attacks of this vulnerability can result in unauthorized read access to a subset of Core RDBMS
    accessible data.(CVE-2022-21247)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  # Note there are no Combo or OJVM patches for 21.x. OJVM fixes are released as part of the RU patches.
  # See note next to 21.x patches for Jan 22'
  {'min_version': '21.0', 'fixed_version': '21.5.0.0.220118', 'missing_patch':'33516412', 'os':'unix', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.5.0.0.220118', 'missing_patch':'33589769', 'os':'win', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.12.2.0.220118', 'missing_patch':'33494256', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.14.0.0.220118', 'missing_patch':'33575656', 'os':'win', 'component':'db'},
  {'min_version': '19.13', 'fixed_version': '19.13.1.0.220118', 'missing_patch':'33516456', 'os':'unix', 'component':'db'},
  {'min_version': '19.14', 'fixed_version': '19.14.0.0.220118', 'missing_patch':'33515361', 'os':'unix', 'component':'db'},

  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.220118', 'missing_patch':'33587128', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.220118', 'missing_patch':'33488333', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.220118', 'missing_patch':'33465249, 33477199', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.220118', 'missing_patch':'33492893', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.14.0.0.220118', 'missing_patch':'33561310', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.14.0.0.220118', 'missing_patch':'33561310', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.220118', 'missing_patch':'33561275', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.220118', 'missing_patch':'33577550', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.220118', 'missing_patch':'33561268', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.220118', 'missing_patch':'33577533', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
