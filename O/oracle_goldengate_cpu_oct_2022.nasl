#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166440);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/04");

  script_cve_id(
    "CVE-2018-18893",
    "CVE-2020-29508",
    "CVE-2020-35163",
    "CVE-2020-35164",
    "CVE-2020-35166",
    "CVE-2020-35167",
    "CVE-2020-35168",
    "CVE-2020-35169",
    "CVE-2020-36518",
    "CVE-2021-36090",
    "CVE-2022-23437"
  );

  script_name(english:"Oracle GoldenGate (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GoldenGate installed on the remote host are affected by multiple vulnerabilities as referenced in the
October 2022 CPU advisory.

  - Vulnerability in Oracle GoldenGate (component: Oracle GoldenGate Microservices (Dell BSAFE Micro Edition
    Suite)).   The supported version that is affected is 19c. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTPS to compromise Oracle GoldenGate.  Successful
    attacks of this vulnerability can result in takeover of Oracle GoldenGate. (CVE-2020-35169)

  - Vulnerability in the Oracle Goldengate product of Oracle GoldenGate (component: Stream Analytics
    (JinJava)). The supported version that is affected is 19c. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle Goldengate.  Successful attacks of
    this vulnerability can result in  unauthorized read access to a subset of Oracle Goldengate accessible
    data. (CVE-2018-18893)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_installed.nbin");
  script_require_keys("Oracle/GoldenGate/Installed");

  exit(0);
}

include('vcf_extras_oracle.inc');
include('debug.inc');

var app_info = vcf::oracle_goldengate::get_app_info();

var constraints = [
  {
    'min_version'   : '19.1',
    'fixed_version' : '19.1.0.0.221018',
    'fixed_display' : '19.1.0.0.221018 (34648537 / 34653308 / 34653311 / 34653323)'
  },
  {
    'min_version'   : '21.3',
    'fixed_version' : '21.8.0.0.0',
    'fixed_display' : '21.8.0.0.0 (34686059 / 34686071)'
  }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
