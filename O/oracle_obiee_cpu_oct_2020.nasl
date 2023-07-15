#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171961);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2020-14864");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Oracle Business Intelligence Enterprise Edition (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Enterprise Edition 12.2.1.3 and 12.2.1.4 installed on the remote
host are affected by a vulnerability as referenced in the October 2020 CPU advisory. The vulnerability lies in the 
Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Installation). Easily
exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business
Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized access to critical
data or complete access to all Oracle Business Intelligence Enterprise Edition accessible data.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14864");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_business_intelligence_enterprise_edition_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Enterprise Edition");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Enterprise Edition');

# based on Oracle CPU data
var constraints = [
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.201020', 'fixed_display': '12.2.1.3.201020 patch: 31690029'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.201020', 'fixed_display': '12.2.1.4.201020 patch: 31690037'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);