#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164340);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2019-0227", "CVE-2022-21523");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Intelligence Publisher (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the remote host is 12.2.1.3.x prior to 
12.2.1.3.220628, 12.2.1.4.x prior to 12.2.1.3.220628, It is, therefore, affected by multiple vulnerabilities as noted 
in the July 2022 Critical Patch Update advisory, including the following:

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: BI Publisher Security 
    (Apache Axis)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Difficult to exploit 
    vulnerability allows unauthenticated attacker with access to the physical communication segment attached to the 
    hardware where the Oracle BI Publisher executes to compromise Oracle BI Publisher. Successful attacks of this 
    vulnerability can result in takeover of Oracle BI Publisher. (CVE-2019-0227)

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: BI Publisher Security). 
    Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows low 
    privileged attacker with network access via HTTP to compromise Oracle BI Publisher. Successful attacks of this 
    vulnerability can result in unauthorized read access to a subset of Oracle BI Publisher accessible data.
    (CVE-2022-21523)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

var constraints = [
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.220628', 'patch': '34329732', 'bundle': '34329732'}, 
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.220628', 'patch': '34329737', 'bundle': '34329737'}, 
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
