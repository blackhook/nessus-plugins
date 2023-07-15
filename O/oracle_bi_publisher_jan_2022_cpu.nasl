#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157405);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2022-21346");

  script_name(english:"Oracle Business Intelligence Publisher (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: BI Publisher Security). 
Supported versions that are affected are 5.5.0.0, 5.9.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability 
allows unauthenticated attacker with network access via HTTP to compromise Oracle BI Publisher. Successful attacks of 
this vulnerability can result in unauthorized access to critical data or complete access to all Oracle BI Publisher 
accessible data.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21346");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/07");

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

app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

constraints = [
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.211214', 'patch': '33671064', 'bundle': '33671064'}, 
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.211207', 'patch': '33642477', 'bundle': '33642477'}, 
  # Oracle Analytics Server 5.5
  {'min_version': '12.2.5.5', 'fixed_version': '12.2.5.5.211223', 'patch': '33702981', 'bundle': '33702981'},
  {'min_version': '12.2.5.9', 'fixed_version': '12.2.5.9.211223', 'patch': '33702984', 'bundle': '33702984'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
