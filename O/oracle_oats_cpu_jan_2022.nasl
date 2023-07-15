#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156933);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/20");

  script_cve_id("CVE-2021-2351");

  script_name(english:"Oracle Application Testing Suite (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 13.3.0.1 versions of Application Testing Suite installed on the remote host are affected by a vulnerability as
referenced in the January 2022 CPU advisory.

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component: Load Testing
    for Web Apps (JDBC, OCCI)). The supported version that is affected is 13.3.0.1. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via Oracle Net to compromise Oracle Application Testing Suite.
    Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Oracle Application Testing Suite, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in takeover of Oracle Application Testing Suite. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all
all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_oats::get_app_info();

var patches_to_report;
var patches_to_check;
if (get_kb_item('SMB/Registry/Enumerated'))
{
  patches_to_report = make_list('33755762');
}
else
{
  patches_to_report = make_list('33755762', '33755751');
  patches_to_check = make_list('33755751');
}

var constraints = [
  { 'min_version' : '13.3.0.1', 'fixed_version' : '13.3.0.1.422' }
];

vcf::oracle_oats::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints,
  patches_to_report:patches_to_report,
  patches_to_check:patches_to_check
);
