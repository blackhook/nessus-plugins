#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156890);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2019-10086",
    "CVE-2020-6950",
    "CVE-2022-21250",
    "CVE-2022-21251",
    "CVE-2022-21255",
    "CVE-2022-21273",
    "CVE-2022-21274",
    "CVE-2022-21354",
    "CVE-2022-21373"
  );
  script_xref(name:"IAVA", value:"2022-A-0033-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle E-Business Suite (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2022 CPU advisory.

  - Vulnerability in the Oracle Sourcing product of Oracle E-Business Suite (component: Intelligence, RFx
    Creation). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Oracle Sourcing. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Oracle Sourcing accessible data as well as unauthorized access to critical data or
    complete access to all Oracle Sourcing accessible data. (CVE-2022-21274)

  - Vulnerability in the Oracle Project Costing product of Oracle E-Business Suite (component: Expenses,
    Currency Override). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Project
    Costing. Successful attacks of this vulnerability can result in unauthorized creation, deletion or
    modification access to critical data or all Oracle Project Costing accessible data as well as unauthorized
    access to critical data or complete access to all Oracle Project Costing accessible data. (CVE-2022-21273)

  - Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: UI Servlet).
    Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle Configurator. Successful attacks of
    this vulnerability can result in unauthorized creation, deletion or modification access to critical data
    or all Oracle Configurator accessible data as well as unauthorized access to critical data or complete
    access to all Oracle Configurator accessible data. (CVE-2022-21255)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10086");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21274");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.3', 'max_version' : '12.2.10.99999999', 'fix_patches' : '33487428' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '33487428, 33568131' },
];

var fix_date = '202201';

vcf::oracle_ebusiness::check_version_and_report(
  app_info    : app_info,
  severity    : SECURITY_HOLE,
  constraints : constraints,
  fix_date    : fix_date
);

