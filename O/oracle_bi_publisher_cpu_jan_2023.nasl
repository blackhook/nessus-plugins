#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170495);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/25");

  script_cve_id("CVE-2023-21832", "CVE-2023-21846");

  script_name(english:"Oracle Business Intelligence Publisher (OBIEE) (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 5.9.0.0 and 6.4.0.0 versions of Oracle Business Intelligence Enterprise Edition installed on the remote host are
affected by multiple vulnerabilities as referenced in the January 2023 CPU advisory.

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Security).
    Supported versions that are affected are 5.9.0.0.0, 6.4.0.0.0 and 12.2.1.4.0. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    Oracle BI Publisher. Successful attacks of this vulnerability can result in takeover of Oracle BI
    Publisher. (CVE-2023-21832)

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Security).
    Supported versions that are affected are 5.9.0.0.0, 6.4.0.0.0 and 12.2.1.4.0. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    Oracle BI Publisher. Successful attacks of this vulnerability can result in takeover of Oracle BI
    Publisher. (CVE-2023-21846)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

# based on Oracle CPU data
var constraints = [
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.230102', 'patch': '34939406', 'bundle': '34978711'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
