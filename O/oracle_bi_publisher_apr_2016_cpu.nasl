#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130268);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-3576", "CVE-2016-0468", "CVE-2016-0479");
  script_bugtraq_id(76272, 86446, 86464);

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (April 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the remote host is 11.1.1.7.x prior to 11.1.1.7.160119,
11.1.1.9.x prior to 11.1.1.9.160119, or 12.2.1.0.x prior to 12.2.1.0.160419. It is, therefore, affected by multiple
vulnerabilities as noted in the April 2016 Critical Patch Update advisory. These vulnerabilities are as follows:

  - An unspecified vulnerability in the Oracle Business Intelligence Enterprise Edition component in Oracle
    Fusion Middleware which allows remote, authenticated users to affect confidentiality and integrity via
    vectors related to Analytics Web General (CVE-2016-0468).

  - An unspecified vulnerability in the Oracle Business Intelligence Enterprise Edition component in Oracle
    Fusion Middleware which allows remote attackers to affect confidentiality and integrity via vectors
    related to Analytics Scorecard (CVE-2016-0479).

  - The processControlCommand function in broker/TransportConnection.java in Apache ActiveMQ before 5.11.0,
    used by Oracle Business Intelligence Publisher, allows remote attackers to cause a denial of service
    (shutdown) via a shutdown command (CVE-2014-3567).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb7b96f");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2016 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin", "oracle_bi_publisher_detect.nasl");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
appname = 'Oracle Business Intelligence Publisher';
app_info = vcf::get_app_info(app:appname);

# Bundle numbers come from April 2016 CPU Fusion Middleware, patch numbers come from docs as noted below
# 11.1.1.7.x - Bundle: 22225110 | Patch: 22225969 from Doc ID 1276869.1
# 11.1.1.9.x - Bundle: 22393988 | Patch: 22382217 from Doc ID 1276869.1
# 12.2.1.0.x - Bundle: 22734181 | Patch: 22734181 (Doc ID 2147699.1 has no specific patch)
constraints = [
  {'min_version': '11.1.1.7', 'fixed_version': '11.1.1.7.160119', 'patch': '22225969', 'bundle': '22225110'},
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.160119', 'patch': '22382217', 'bundle': '22393988'},
  {'min_version': '12.2.1.0', 'fixed_version': '12.2.1.0.160419', 'patch': '22734181', 'bundle': '22734181'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
