#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156931);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-36090");
  script_xref(name:"IAVA", value:"2022-A-0029");

  script_name(english:"Oracle Business Process Management Suite (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
(component: Installer (Apache Commons Compress)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0.
Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
Business Process Management Suite. Successful attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of Oracle Business Process Management Suite.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36090");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Oracle Business Process Manager');

var constraints = [
  { 'min_version':'12.2.1.3.0', 'fixed_version' : '12.2.1.3.211221' },
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.211221' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
