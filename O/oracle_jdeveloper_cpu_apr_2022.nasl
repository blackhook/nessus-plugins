#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160204);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2021-44832", "CVE-2022-21445", "CVE-2022-23305");
  script_xref(name:"IAVA", value:"2022-A-0171");

  script_name(english:"Oracle JDeveloper Multiple Vulnerabilities (April 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is missing a security patch. It is, therefore, affected by 
multiple vulnerabilities as referenced in the April 2022 CPU advisory:

  - Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: Oracle JDeveloper 
    (Apache Log4j)). The supported version that is affected is 12.2.1.4.0. Difficult to exploit vulnerability 
    allows high privileged attacker with network access via HTTP to compromise Oracle JDeveloper. Successful 
    attacks of this vulnerability can result in takeover of Oracle JDeveloper. (CVE-2021-44832)

  - Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: ADF Faces). 
    Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle JDeveloper. Successful 
    attacks of this vulnerability can result in takeover of Oracle JDeveloper. (CVE-2022-21445)

  - Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: Oracle JDeveloper 
    (Apache Log4j)). The supported version that is affected is 12.2.1.3.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle JDeveloper. Successful 
    attacks of this vulnerability can result in takeover of Oracle JDeveloper. (CVE-2022-23305)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'12.2.1.3', 'fixed_version':'12.2.1.3.220310', 'missing_patch':'33949366' },
  { 'min_version':'12.2.1.4', 'fixed_version':'12.2.1.4.220314', 'missing_patch':'33958532' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_HOLE,
  constraints:constraints
);
