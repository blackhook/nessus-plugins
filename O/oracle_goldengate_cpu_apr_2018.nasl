#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134306);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-2832");
  script_bugtraq_id(103843);

  script_name(english:"Oracle GoldenGate Information Disclosure (April 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A real-time data integration and replication application installed on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle GoldenGate installed on the remote host is affected by an information disclosure vulnerability,
as noted in the April 2018 CPU advisory. The vulnerability exists in Oracle GoldenGate due to an unknown reason. An
unauthenticated, remote attacker can exploit this, via HTTP, to disclose potentially sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2018.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2353306.1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_installed.nbin");
  script_require_keys("Oracle/GoldenGate/Installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_goldengate::get_app_info();

var constraints = [
  {
    'min_version'   : '12.2.0.1' ,
    'fixed_version' : '12.2.0.1.161018',
    'fixed_display' : '12.2.0.1.161018 (24764941 / 24764950 / 24764985 / 24765017)'
  }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
