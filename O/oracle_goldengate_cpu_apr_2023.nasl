#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174481);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id("CVE-2022-42003", "CVE-2022-42004", "CVE-2022-45047");

  script_name(english:"Oracle GoldenGate (April 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GoldenGate installed on the remote host are affected by multiple vulnerabilities as referenced in the
October 2022 CPU advisory.

  - Vulnerabilities in Oracle GoldenGate (component: Oracle GoldenGate (jackson-databind)). Supported versions
    that are affected are Prior to 19.1.0.0.230418 and Prior to 21.10.0.0.0. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Oracle GoldenGate. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of Oracle GoldenGate. (CVE-2022-42003, CVE-2022-42004)

  - Security-in-Depth issue in Oracle GoldenGate (component: Oracle GoldenGate (Apache Mina SSHD)).
    This vulnerability cannot be exploited in the context of this product. (CVE-2022-45047)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Vectors in accordance with vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'fixed_version' : '19.1.0.0.230418',
    'fixed_display' : '19.1.0.0.230418 (35275310 / 35275313 / 35275317 / 35275319 / 35326279)'
  },
  {
    'min_version'   : '21.0',
    'fixed_version' : '21.10.0.0.0',
    'fixed_display' : '21.10.0.0.0 (35271080 / 35271078)'
  }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
