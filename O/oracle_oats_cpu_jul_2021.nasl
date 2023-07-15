#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152043);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-10086");
  script_xref(name:"IAVA", value:"2021-A-0345");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Application Testing Suite (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 13.3.0.1 versions of Application Testing Suite installed on the remote host are affected by a vulnerability as
referenced in the July 2021 CPU advisory.

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component:
    Load Testing for Web Apps (Apache Commons BeanUtils)). The supported version that is affected is 13.3.0.1.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle Application Testing Suite. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Application Testing Suite accessible data
    as well as unauthorized read access to a subset of Oracle Application Testing Suite accessible data and
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Application Testing
    Suite. (CVE-2019-10086)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all
all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10086");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  patches_to_report = make_list('32690142');
}
else
{
  patches_to_report = make_list('32690142', '32690139');
  patches_to_check = make_list('32690139');
}

var constraints = [
  { 'min_version' : '13.3.0.1', 'fixed_version' : '13.3.0.1.402' }
];

vcf::oracle_oats::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_HOLE,
  constraints:constraints,
  patches_to_report:patches_to_report,
  patches_to_check:patches_to_check
);
