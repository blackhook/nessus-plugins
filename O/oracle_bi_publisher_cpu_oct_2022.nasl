#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166338);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-21590", "CVE-2022-25647");

  script_name(english:"Oracle Business Intelligence Publisher (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 5.9.0.0 and 6.4.0.0 versions of Oracle Business Intelligence Enterprise Edition installed on the remote host are
affected by multiple vulnerabilities as referenced in the October 2022 CPU advisory.

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Core 
    Formatting API). Supported versions that are affected are 5.9.0.0, 6.4.0.0.0, 12.2.1.3.0 and 12.2.1.4.0. 
    Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to 
    compromise Oracle BI Publisher. Successful attacks of this vulnerability can result in unauthorized 
    access to critical data or complete access to all Oracle BI Publisher accessible data as well as 
    unauthorized update, insert or delete access to some of Oracle BI Publisher accessible data and 
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle BI Publisher. 
    (CVE-2022-21590)

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Security 
    (Google Gson)). Supported versions that are affected are 5.9.0.0, 6.4.0.0.0, 12.2.1.3.0 and 12.2.1.4.0. 
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to 
    compromise Oracle BI Publisher. Successful attacks of this vulnerability can result in unauthorized 
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle BI Publisher. 
    (CVE-2022-25647)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

# based on Oracle CPU data
var constraints = [
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.220922', 'patch': '34630308', 'bundle': '34703515'}, 
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.220926', 'patch': '34639569', 'bundle': '34703649'}, 
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
